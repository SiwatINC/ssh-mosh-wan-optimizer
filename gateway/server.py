"""
AsyncSSH server that accepts local SSH client connections and bridges them
to remote servers via MOSH.

Authentication pass-through model
----------------------------------
  • The SSH login username becomes the remote username.
  • The client's SSH agent is forwarded and used to authenticate to the
    remote server — the gateway holds no keys of its own.
  • Connect from your local machine with:  ssh -A user@gateway -p 2222

Client → Gateway authentication modes (pick one):
  • Public key  (authorized_keys file or inline content)  — recommended
  • Password    (user:password pairs in config)
  • Accept-any  (skip validation)                         — dev / trusted LAN only
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
        return True  # always require authentication

    # --- Public key ---

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        if self._config.accept_any_key:
            logger.warning(
                "GATEWAY_ACCEPT_ANY_KEY=true — accepting key for '%s' without validation",
                username,
            )
            return True

        auth_keys_text = self._config.effective_authorized_keys
        if not auth_keys_text:
            logger.warning(
                "No authorized_keys configured; rejecting public-key auth for '%s'", username
            )
            return False

        try:
            auth_keys = asyncssh.import_authorized_keys(auth_keys_text)
            # validate() returns None on success, an exception reason string on failure
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
        logger.info("Session requested by '%s'", username)
        return self._session_factory(username)


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------


async def run_gateway(config: GatewayConfig) -> None:
    """Start the SSH gateway and run forever."""

    def session_factory(ssh_username: str) -> GatewaySession:
        try:
            remote_user, remote_host, remote_port = config.parse_destination(ssh_username)
        except ValueError as exc:
            logger.error("Destination parse error for '%s': %s", ssh_username, exc)
            # Return a session that will immediately report the error
            remote_user, remote_host, remote_port = ssh_username, "", config.default_remote_port

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
        agent_forwarding=True,  # tell asyncssh to handle agent-forwarding requests
    )

    logger.info("SSH↔MOSH gateway listening on %s:%d", config.host, config.port)
    logger.info(
        "Authentication: passed through via client SSH agent (ssh -A ...)"
    )
    if config.default_remote_host:
        logger.info("Default target: *@%s:%d", config.default_remote_host, config.default_remote_port)
    else:
        logger.info("Dynamic routing: SSH username format 'user@remotehost[:port]'")

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
