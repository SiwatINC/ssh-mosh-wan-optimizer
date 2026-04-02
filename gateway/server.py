"""
AsyncSSH server that accepts local SSH client connections and bridges them
to a single, fixed remote server via MOSH.

Security model
--------------
  • The remote target (host + port) is FIXED at startup.  Clients cannot
    redirect connections to arbitrary hosts.
  • SSH usernames are validated against a strict allowlist pattern
    ([a-zA-Z0-9._-]{1,64}) and rejected immediately on mismatch.
  • Authentication to the remote server is passed through via the client's
    forwarded SSH agent — the gateway holds no credentials of its own.
  • Connect from your local machine with:  ssh -A user@gateway -p 2222

Client → Gateway authentication modes (configure exactly one):
  • Public key  (authorized_keys file or inline content)  — recommended
  • Password    (user:password pairs in config)
  • Accept-any  (no validation)                           — dev / trusted LAN only
"""

import asyncio
import logging
import os
from typing import Callable, Optional

import asyncssh

from .config import GatewayConfig
from .session import GatewaySession

logger = logging.getLogger(__name__)


class _GatewaySSHServer(asyncssh.SSHServer):
    """One instance per accepted TCP connection."""

    def __init__(self, config: GatewayConfig, session_factory: Callable):
        self._config = config
        self._session_factory = session_factory
        self._conn: Optional[asyncssh.SSHServerConnection] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        logger.info("New connection from %s", peer)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.debug("Connection lost: %s", exc)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def begin_auth(self, username: str) -> bool:
        """
        Called before any auth method is tried.

        Immediately disconnect clients that supply an invalid username —
        before they get to attempt any authentication.
        """
        if not GatewayConfig.is_valid_username(username):
            peer = self._conn.get_extra_info("peername") if self._conn else "unknown"
            logger.warning(
                "Disconnecting %s: invalid username %r (must match [a-zA-Z0-9._-]{1,64})",
                peer,
                username,
            )
            if self._conn:
                self._conn.disconnect(
                    asyncssh.DISC_ILLEGAL_USER_NAME,
                    "Invalid username format",
                )
        return True  # always require auth

    # --- Public key ---

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        # Defence-in-depth: re-check username even though begin_auth already did.
        if not GatewayConfig.is_valid_username(username):
            return False

        if self._config.accept_any_key:
            logger.warning(
                "GATEWAY_ACCEPT_ANY_KEY=true — accepting key for '%s' without validation",
                username,
            )
            return True

        auth_keys_text = self._config.effective_authorized_keys
        if not auth_keys_text:
            # No local authorized_keys configured: delegate entirely to the remote.
            # The client's agent will be used to authenticate to the remote server;
            # if the remote rejects it the MOSH bootstrap fails and the session ends.
            logger.info(
                "No local authorized_keys — accepting key for '%s', remote server is the auth gate",
                username,
            )
            return True

        try:
            auth_keys = asyncssh.import_authorized_keys(auth_keys_text)
            # validate() returns None on success, a reason string on failure
            if auth_keys.validate(key, username) is None:
                logger.info("Public key accepted for '%s'", username)
                return True
        except Exception as exc:
            logger.error("Error validating public key for '%s': %s", username, exc)

        logger.info("Public key rejected for '%s'", username)
        return False

    # --- Password ---

    def password_auth_supported(self) -> bool:
        return self._config.password_auth

    def validate_password(self, username: str, password: str) -> bool:
        if not GatewayConfig.is_valid_username(username):
            return False

        expected = self._config.passwords.get(username)
        if expected is not None and expected == password:
            logger.info("Password auth accepted for '%s'", username)
            return True
        logger.warning("Password auth failed for '%s'", username)
        return False

    # ------------------------------------------------------------------
    # Session dispatch
    # ------------------------------------------------------------------

    def session_requested(self) -> asyncssh.SSHServerSession:
        assert self._conn is not None
        username = self._conn.get_extra_info("username", "")
        logger.info("Session opened: user='%s' target=%s:%d",
                    username, self._config.remote_host, self._config.remote_port)
        return self._session_factory(username)


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------


async def run_gateway(config: GatewayConfig) -> None:
    """
    Start the SSH gateway and run forever.

    ``config.remote_host`` must be set; ``GatewayConfig.__init__`` already
    raises ``ConfigError`` if it is missing, so we just assert here.
    """
    assert config.remote_host, "remote_host must be set before calling run_gateway()"

    def session_factory(ssh_username: str) -> GatewaySession:
        remote_user, remote_host, remote_port = config.get_remote_destination(ssh_username)
        return GatewaySession(
            remote_host=remote_host,
            remote_user=remote_user,
            remote_port=remote_port,
            known_hosts=config.remote_known_hosts,
            ignore_host_key=config.remote_ignore_host_key,
        )

    host_key = _ensure_host_key(config.host_key_path)

    server = await asyncssh.create_server(
        lambda: _GatewaySSHServer(config, session_factory),
        host=config.host,
        port=config.port,
        server_host_keys=[host_key],
        encoding=None,          # raw bytes in sessions
        agent_forwarding=True,  # handle agent-forwarding channel requests
    )

    logger.info("SSH↔MOSH gateway listening on %s:%d", config.host, config.port)
    logger.info("Fixed remote target: %s:%d", config.remote_host, config.remote_port)
    logger.info("Auth: client SSH agent forwarded to remote (ssh -A ...)")

    async with server:
        await asyncio.get_event_loop().create_future()  # run forever


def _ensure_host_key(path: str) -> asyncssh.SSHKey:
    """Load the existing host key or generate a new ed25519 one."""
    if os.path.exists(path):
        return asyncssh.read_private_key(path)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(path)
    os.chmod(path, 0o600)
    logger.info("Generated new host key at %s", path)
    return key
