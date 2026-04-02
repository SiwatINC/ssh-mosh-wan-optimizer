"""
SSH server session handler.

Each authenticated SSH client session is handled by one GatewaySession
instance, which:
  1. Accepts the PTY and shell requests from the SSH client.
  2. Bootstraps a MOSH connection to the remote server.
  3. Runs mosh-client in a local PTY subprocess.
  4. Bridges I/O bidirectionally:
       SSH client ←→ asyncssh channel ←→ mosh-client PTY ←→ MOSH/UDP ←→ remote
"""

import asyncio
import logging
import os
from typing import Optional

import asyncssh

from .mosh_bridge import MoshBootstrapError, MoshBridge

logger = logging.getLogger(__name__)

_BANNER = (
    "\r\n"
    "  ╔══════════════════════════════════════╗\r\n"
    "  ║   SSH ↔ MOSH WAN Gateway             ║\r\n"
    "  ╚══════════════════════════════════════╝\r\n"
    "\r\n"
)


class GatewaySession(asyncssh.SSHServerSession):
    """Bridges one SSH client session to a remote server via MOSH."""

    def __init__(
        self,
        remote_host: str,
        remote_user: str,
        remote_port: int = 22,
        ssh_key_path: Optional[str] = None,
    ):
        self._remote_host = remote_host
        self._remote_user = remote_user
        self._remote_port = remote_port
        self._ssh_key_path = ssh_key_path

        self._chan: Optional[asyncssh.SSHServerChannel] = None
        self._bridge: Optional[MoshBridge] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._cols: int = 80
        self._rows: int = 24

    # ------------------------------------------------------------------
    # asyncssh callbacks
    # ------------------------------------------------------------------

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan
        self._loop = asyncio.get_event_loop()

    def pty_requested(
        self,
        term_type: str,
        term_size: tuple,
        term_modes: dict,
    ) -> bool:
        self._cols = term_size[0] or 80
        self._rows = term_size[1] or 24
        logger.debug("PTY requested: %s %dx%d", term_type, self._cols, self._rows)
        return True

    def terminal_size_changed(
        self, width: int, height: int, pixwidth: int, pixheight: int
    ) -> None:
        self._cols = width or self._cols
        self._rows = height or self._rows
        if self._bridge:
            self._bridge.resize(self._cols, self._rows)

    def shell_requested(self) -> bool:
        return True

    def exec_requested(self, command: str) -> bool:
        # We do not support exec mode; interactive sessions only.
        logger.info("exec_requested rejected: %r", command)
        return False

    def session_started(self) -> None:
        asyncio.ensure_future(self._run())

    def data_received(self, data, datatype) -> None:
        """Forward SSH client keystrokes → mosh-client PTY."""
        if self._bridge and self._bridge.master_fd is not None:
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            try:
                os.write(self._bridge.master_fd, data)
            except OSError as exc:
                logger.debug("Write to mosh-client PTY failed: %s", exc)

    def eof_received(self) -> None:
        logger.debug("EOF from SSH client")
        self._cleanup()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.info("SSH client disconnected: %s", exc)
        self._cleanup()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        """Bootstrap MOSH and start the I/O bridge."""
        assert self._chan is not None
        assert self._loop is not None

        self._chan.write(_BANNER)
        self._chan.write(
            f"  Connecting to {self._remote_user}@{self._remote_host}"
            f":{self._remote_port} via MOSH ...\r\n\r\n"
        )

        bridge = MoshBridge(
            remote_host=self._remote_host,
            remote_user=self._remote_user,
            remote_port=self._remote_port,
            ssh_key_path=self._ssh_key_path,
        )
        self._bridge = bridge

        try:
            await bridge.bootstrap()
            master_fd = bridge.connect(cols=self._cols, rows=self._rows)
        except MoshBootstrapError as exc:
            logger.error("MOSH bootstrap failed: %s", exc)
            self._chan.write(f"\r\n\x1b[31mError:\x1b[0m {exc}\r\n")
            self._chan.exit(1)
            return
        except Exception as exc:
            logger.exception("Unexpected error starting MOSH bridge")
            self._chan.write(f"\r\n\x1b[31mInternal error:\x1b[0m {exc}\r\n")
            self._chan.exit(1)
            return

        # Register a reader so we get notified when mosh-client has output.
        self._loop.add_reader(master_fd, self._on_mosh_readable)

    def _on_mosh_readable(self) -> None:
        """Called by the event loop when mosh-client has data to send to the SSH client."""
        assert self._bridge is not None
        assert self._chan is not None
        assert self._loop is not None

        master_fd = self._bridge.master_fd
        if master_fd is None:
            return

        try:
            data = os.read(master_fd, 65536)
        except OSError:
            data = b""

        if not data:
            self._loop.remove_reader(master_fd)
            logger.info("mosh-client closed; ending SSH session")
            try:
                self._chan.exit(0)
            except Exception:
                pass
            return

        try:
            self._chan.write_bytes(data)
        except Exception as exc:
            logger.debug("Write to SSH client failed: %s", exc)

    def _cleanup(self) -> None:
        if self._loop and self._bridge and self._bridge.master_fd is not None:
            try:
                self._loop.remove_reader(self._bridge.master_fd)
            except Exception:
                pass
        if self._bridge:
            self._bridge.terminate()
            self._bridge = None
