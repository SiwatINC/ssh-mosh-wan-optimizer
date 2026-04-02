"""
MOSH bridge: bootstrap mosh-server on the remote via asyncssh (using the
client's forwarded SSH agent for authentication), then start mosh-client
locally in a PTY and expose its file descriptor for I/O bridging.
"""

import asyncio
import fcntl
import logging
import os
import pty
import signal
import struct
import subprocess
import termios
from typing import Optional, Tuple

import asyncssh

logger = logging.getLogger(__name__)

# asyncssh sentinel: skip remote host-key verification entirely
_IGNORE_HOST_KEYS = asyncssh.PermissiveMissingHostKeyPolicy


class MoshBootstrapError(Exception):
    """Raised when we cannot establish the MOSH connection."""


class MoshBridge:
    """
    Manages one MOSH client session bridged to a remote SSH server.

    Authentication to the remote server is **passed through** from the
    local SSH client via its forwarded SSH agent (``agent_path``).

    Typical usage::

        bridge = MoshBridge(
            remote_host="10.0.0.1",
            remote_user="ubuntu",
            agent_path="/tmp/ssh-XXXX/agent.1234",   # from chan.get_agent_path()
        )
        port, key = await bridge.bootstrap()
        master_fd  = bridge.connect(cols=220, rows=50)
        # bridge.master_fd  — PTY fd for bidirectional I/O
        # bridge.resize(cols, rows)  — on window-change
        # bridge.terminate()         — on disconnect
    """

    def __init__(
        self,
        remote_host: str,
        remote_user: str,
        remote_port: int = 22,
        agent_path: Optional[str] = None,
        known_hosts: Optional[str] = None,
        ignore_host_key: bool = False,
    ):
        self.remote_host = remote_host
        self.remote_user = remote_user
        self.remote_port = remote_port
        self.agent_path = agent_path
        self.known_hosts = known_hosts          # path to a known_hosts file, or None → system default
        self.ignore_host_key = ignore_host_key  # True → accept any remote host key

        self.master_fd: Optional[int] = None
        self._process: Optional[subprocess.Popen] = None
        self._mosh_port: Optional[int] = None
        self._mosh_key: Optional[str] = None

    # ------------------------------------------------------------------
    # Bootstrap via asyncssh (uses the forwarded agent for auth)
    # ------------------------------------------------------------------

    async def bootstrap(self) -> Tuple[int, str]:
        """
        Open an asyncssh connection to the remote server and start mosh-server.
        Returns ``(udp_port, mosh_key)``.

        Authentication is performed using the SSH agent reachable at
        ``self.agent_path`` (the client's forwarded agent socket).
        """
        if not self.agent_path:
            raise MoshBootstrapError(
                "No SSH agent forwarding available.  "
                "Connect with agent forwarding enabled: ssh -A ..."
            )

        connect_kwargs: dict = {
            "host": self.remote_host,
            "port": self.remote_port,
            "username": self.remote_user,
            "agent_path": self.agent_path,
        }

        if self.ignore_host_key:
            connect_kwargs["known_hosts"] = None
            logger.warning(
                "Remote host-key verification disabled (REMOTE_IGNORE_HOST_KEY=true)"
            )
        elif self.known_hosts:
            connect_kwargs["known_hosts"] = self.known_hosts
        # else: asyncssh uses system known_hosts by default

        logger.info(
            "Bootstrapping MOSH: %s@%s:%d (agent=%s)",
            self.remote_user,
            self.remote_host,
            self.remote_port,
            self.agent_path,
        )

        try:
            async with asyncssh.connect(**connect_kwargs) as conn:
                result = await asyncio.wait_for(
                    conn.run(
                        "mosh-server new -s -c 256 -l LANG=en_US.UTF-8",
                        check=False,
                    ),
                    timeout=30,
                )
        except asyncio.TimeoutError:
            raise MoshBootstrapError(
                f"Timed out waiting for mosh-server on {self.remote_host}"
            )
        except asyncssh.DisconnectError as exc:
            raise MoshBootstrapError(f"SSH connection to {self.remote_host} failed: {exc}")
        except asyncssh.PermissionDenied:
            raise MoshBootstrapError(
                f"Permission denied authenticating to {self.remote_user}@{self.remote_host}.  "
                "Make sure the forwarded agent holds a key accepted by the remote server."
            )
        except Exception as exc:
            raise MoshBootstrapError(
                f"Could not connect to {self.remote_host}: {exc}"
            ) from exc

        # mosh-server -s prints "MOSH CONNECT <port> <key>" to stdout;
        # some builds emit it on stderr — search both.
        combined = (result.stdout or "") + (result.stderr or "")
        for line in combined.splitlines():
            line = line.strip()
            if line.startswith("MOSH CONNECT"):
                parts = line.split()
                if len(parts) >= 4:
                    self._mosh_port = int(parts[2])
                    self._mosh_key = parts[3]
                    logger.info("mosh-server started: UDP port=%d", self._mosh_port)
                    return self._mosh_port, self._mosh_key

        raise MoshBootstrapError(
            f"Could not parse 'MOSH CONNECT' from server output:\n{combined[:400]}"
        )

    # ------------------------------------------------------------------
    # Connect mosh-client (PTY subprocess)
    # ------------------------------------------------------------------

    def connect(self, cols: int = 80, rows: int = 24) -> int:
        """
        Start ``mosh-client`` in a PTY.
        Returns the master fd; use ``os.read`` / ``os.write`` on it.
        """
        if self._mosh_port is None or self._mosh_key is None:
            raise RuntimeError("Call bootstrap() before connect()")

        master_fd, slave_fd = pty.openpty()
        _set_winsize(slave_fd, rows, cols)

        env = os.environ.copy()
        env["MOSH_KEY"] = self._mosh_key
        env["TERM"] = "xterm-256color"
        env["MOSH_PREDICTION_DISPLAY"] = "adaptive"
        env["COLORTERM"] = "truecolor"

        self._process = subprocess.Popen(
            ["mosh-client", self.remote_host, str(self._mosh_port)],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave_fd)
        self.master_fd = master_fd
        logger.info(
            "mosh-client started (pid=%d, fd=%d)", self._process.pid, master_fd
        )
        return master_fd

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def resize(self, cols: int, rows: int) -> None:
        """Update PTY window size and notify mosh-client via SIGWINCH."""
        if self.master_fd is not None:
            _set_winsize(self.master_fd, rows, cols)
        if self._process is not None:
            try:
                self._process.send_signal(signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def is_alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def terminate(self) -> None:
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            self._process = None

        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
