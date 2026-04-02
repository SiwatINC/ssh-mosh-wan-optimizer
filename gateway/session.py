"""
SSH server session handler.

Each authenticated SSH client session is handled by one GatewaySession
instance, which:
  1. Accepts PTY, agent-forwarding, and shell requests from the SSH client.
  2. Passes the client's forwarded SSH agent through to the remote server
     for authentication (no gateway-owned keys required).
  3. Bootstraps a MOSH connection to the remote server.
  4. Runs mosh-client in a local PTY subprocess.
  5. Bridges I/O bidirectionally:
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
    """
    Bridges one SSH client session to a remote server via MOSH.

    Authentication to the remote server is passed through using the
    client's forwarded SSH agent (``ssh -A``).  The SSH login username
    becomes the remote username.
    """

    def __init__(
        self,
        remote_host: str,
        remote_user: str,
        remote_port: int = 22,
        known_hosts: Optional[str] = None,
        ignore_host_key: bool = False,
    ):
        self._remote_host = remote_host
        self._remote_user = remote_user
        self._remote_port = remote_port
        self._known_hosts = known_hosts
        self._ignore_host_key = ignore_host_key

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

    def agent_forwarding_requested(self) -> bool:
        """Accept the client's SSH agent so we can pass it through to the remote."""
        logger.debug("Agent forwarding accepted for %s@%s", self._remote_user, self._remote_host)
        return True

    def shell_requested(self) -> bool:
        return True

    def exec_requested(self, command: str) -> bool:
        logger.info("exec_requested rejected (interactive sessions only): %r", command)
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
        """Pass the client's agent through, bootstrap MOSH, and start I/O bridge."""
        assert self._chan is not None
        assert self._loop is not None

        # Retrieve the forwarded agent socket path that asyncssh set up when
        # agent_forwarding_requested() returned True.
        agent_path: Optional[str] = self._chan.get_agent_path()

        self._chan.write(_BANNER)
        self._chan.write(
            f"  Connecting to {self._remote_user}@{self._remote_host}"
            f":{self._remote_port} via MOSH ...\r\n"
        )
        if not agent_path:
            self._chan.write(
                "\r\n\x1b[33mWarning:\x1b[0m No SSH agent forwarding detected.\r\n"
                "  If authentication fails, reconnect with:  ssh -A ...\r\n\r\n"
            )
        else:
            logger.debug("Using forwarded agent: %s", agent_path)

        self._chan.write("\r\n")

        bridge = MoshBridge(
            remote_host=self._remote_host,
            remote_user=self._remote_user,
            remote_port=self._remote_port,
            agent_path=agent_path,
            known_hosts=self._known_hosts,
            ignore_host_key=self._ignore_host_key,
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

        # Register a reader so we're notified when mosh-client has output.
        self._loop.add_reader(master_fd, self._on_mosh_readable)

    def _on_mosh_readable(self) -> None:
        """Called by the event loop when mosh-client has data for the SSH client."""
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
