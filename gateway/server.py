"""
AsyncSSH server that accepts local SSH client connections and bridges them
to a single, fixed remote server via MOSH.

Security model
--------------
  • The remote target (host + port) is FIXED at startup.
  • SSH usernames are validated against [a-zA-Z0-9._-]{1,64} and rejected
    immediately on mismatch.
  • Client public keys are validated against the remote server's own
    ~/.ssh/authorized_keys fetched via the gateway key (cached, 60 s TTL).
    No separate authorized_keys management on the gateway is needed.

Client → Gateway authentication modes:
  • Remote key store  (default — uses remote's authorized_keys)
  • Local authorized_keys file / inline content  (optional override)
  • Password          (user:password pairs in config)
  • Accept-any        (dev / trusted LAN only)
"""

import asyncio
import logging
import os
import time
from typing import Callable, Dict, Optional, Tuple

import asyncssh

from .config import GatewayConfig
from .session import GatewaySession

logger = logging.getLogger(__name__)

_KEY_CACHE_TTL = 60  # seconds


class _RemoteKeyCache:
    """
    Fetches and caches each user's authorized_keys from the remote server.

    The gateway uses its own SSH key to connect as the requested user and
    runs ``cat ~/.ssh/authorized_keys``.  Results are cached per username
    for ``_KEY_CACHE_TTL`` seconds so repeated auth attempts don't each
    open a new SSH connection.
    """

    def __init__(self, config: GatewayConfig):
        self._config = config
        self._cache: Dict[str, Tuple[str, float]] = {}  # username → (text, timestamp)
        self._lock = asyncio.Lock()

    async def get(self, username: str) -> Optional[str]:
        """Return authorized_keys text for *username*, fetching if stale."""
        now = time.monotonic()

        async with self._lock:
            if username in self._cache:
                text, ts = self._cache[username]
                if now - ts < _KEY_CACHE_TTL:
                    return text

        text = await self._fetch(username)

        if text is not None:
            async with self._lock:
                self._cache[username] = (text, time.monotonic())

        return text

    async def _fetch(self, username: str) -> Optional[str]:
        cfg = self._config
        connect_kwargs: dict = {
            "host": cfg.remote_host,
            "port": cfg.remote_port,
            "username": username,
        }
        if cfg.effective_ssh_key:
            connect_kwargs["client_keys"] = [cfg.effective_ssh_key]
        if cfg.remote_ignore_host_key:
            connect_kwargs["known_hosts"] = None
        elif cfg.remote_known_hosts:
            connect_kwargs["known_hosts"] = cfg.remote_known_hosts

        logger.debug("Fetching authorized_keys from remote for '%s'", username)
        try:
            async with asyncssh.connect(**connect_kwargs) as conn:
                result = await asyncio.wait_for(
                    conn.run("cat ~/.ssh/authorized_keys", check=False),
                    timeout=10,
                )
            text = result.stdout or ""
            logger.debug("Fetched %d bytes of authorized_keys for '%s'", len(text), username)
            return text
        except asyncssh.PermissionDenied:
            logger.warning(
                "Permission denied fetching authorized_keys for '%s' — "
                "gateway key not authorized on remote?",
                username,
            )
        except Exception as exc:
            logger.warning("Could not fetch authorized_keys for '%s': %s", username, exc)
        return None


class _GatewaySSHServer(asyncssh.SSHServer):
    """One instance per accepted TCP connection."""

    def __init__(self, config: GatewayConfig, session_factory: Callable,
                 key_cache: _RemoteKeyCache):
        self._config = config
        self._session_factory = session_factory
        self._key_cache = key_cache
        self._conn: Optional[asyncssh.SSHServerConnection] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        logger.info("New connection from %s", conn.get_extra_info("peername"))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.debug("Connection lost: %s", exc)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def begin_auth(self, username: str) -> bool:
        if not GatewayConfig.is_valid_username(username):
            peer = self._conn.get_extra_info("peername") if self._conn else "unknown"
            logger.warning(
                "Disconnecting %s: invalid username %r", peer, username
            )
            if self._conn:
                self._conn.disconnect(
                    asyncssh.DISC_ILLEGAL_USER_NAME, "Invalid username format"
                )
        return True

    # --- Public key ---

    def public_key_auth_supported(self) -> bool:
        return True

    async def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        if not GatewayConfig.is_valid_username(username):
            return False

        if self._config.accept_any_key:
            logger.warning("GATEWAY_ACCEPT_ANY_KEY — accepting key for '%s'", username)
            return True

        # Local authorized_keys takes precedence if configured.
        auth_keys_text = self._config.effective_authorized_keys
        source = "local"

        if not auth_keys_text:
            # Fall back to remote key store.
            auth_keys_text = await self._key_cache.get(username)
            source = "remote"

        if not auth_keys_text:
            logger.warning(
                "No authorized_keys available for '%s' (remote fetch failed) — rejecting",
                username,
            )
            return False

        try:
            auth_keys = asyncssh.import_authorized_keys(auth_keys_text)
            if auth_keys.validate(key, username) is None:
                logger.info("Public key accepted for '%s' (source: %s)", username, source)
                return True
        except Exception as exc:
            logger.error("Error validating key for '%s': %s", username, exc)

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
    assert config.remote_host, "remote_host must be set before calling run_gateway()"

    key_cache = _RemoteKeyCache(config)

    def session_factory(ssh_username: str) -> GatewaySession:
        remote_user, remote_host, remote_port = config.get_remote_destination(ssh_username)
        return GatewaySession(
            remote_host=remote_host,
            remote_user=remote_user,
            remote_port=remote_port,
            client_key=config.effective_ssh_key,
            known_hosts=config.remote_known_hosts,
            ignore_host_key=config.remote_ignore_host_key,
        )

    host_key = _ensure_host_key(config.host_key_path)

    server = await asyncssh.create_server(
        lambda: _GatewaySSHServer(config, session_factory, key_cache),
        host=config.host,
        port=config.port,
        server_host_keys=[host_key],
        encoding=None,
    )

    logger.info("SSH↔MOSH gateway listening on %s:%d", config.host, config.port)
    logger.info("Remote target: %s:%d", config.remote_host, config.remote_port)
    logger.info("Client auth: remote key store (cache TTL=%ds)", _KEY_CACHE_TTL)

    async with server:
        await asyncio.get_event_loop().create_future()


def _ensure_host_key(path: str) -> asyncssh.SSHKey:
    if os.path.exists(path):
        return asyncssh.read_private_key(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(path)
    os.chmod(path, 0o600)
    logger.info("Generated new host key at %s", path)
    return key
