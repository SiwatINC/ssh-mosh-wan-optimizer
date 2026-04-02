"""Configuration loading from environment variables or YAML."""

import logging
import os
import re
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Allowed SSH usernames: standard Unix usernames only.
# No '@', no shell metacharacters, no path separators.
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,64}$')


class ConfigError(Exception):
    """Raised when the gateway configuration is invalid."""


class GatewayConfig:
    """
    All settings for the SSH↔MOSH gateway.

    The remote target is FIXED at startup via REMOTE_HOST / REMOTE_PORT.
    Clients cannot redirect connections to arbitrary hosts.

    Client → Gateway authentication
    --------------------------------
    GATEWAY_AUTHORIZED_KEYS_PATH    Path to an authorized_keys file
    GATEWAY_AUTHORIZED_KEYS_CONTENT Raw authorized_keys text (newline-separated)
    GATEWAY_ACCEPT_ANY_KEY          "true" to accept any client public key
                                    (dev / trusted LAN only — never in production)
    GATEWAY_PASSWORD_AUTH           "true" to also allow password authentication
    GATEWAY_PASSWORDS               Comma-separated user:password pairs

    Gateway → Remote authentication (agent pass-through)
    -----------------------------------------------------
    The client's SSH agent is forwarded and used to authenticate to the
    fixed remote server.  Connect with:  ssh -A user@gateway -p 2222

    SSH server settings
    -------------------
    GATEWAY_HOST                    Bind address (default: 0.0.0.0)
    GATEWAY_PORT                    SSH listen port (default: 2222)
    GATEWAY_HOST_KEY_PATH           Server host key path (auto-generated if missing)

    Remote MOSH target  (FIXED — no dynamic routing)
    --------------------------------------------------
    REMOTE_HOST                     Remote host to MOSH into  *** REQUIRED ***
    REMOTE_PORT                     Remote SSH port (default: 22)
    REMOTE_KNOWN_HOSTS              Path to a known_hosts file for verifying the remote host key.
                                    Defaults to system known_hosts (~/.ssh/known_hosts).
    REMOTE_IGNORE_HOST_KEY          "true" to skip remote host-key verification (insecure)
    """

    def __init__(
        self,
        # SSH server
        host: str = "0.0.0.0",
        port: int = 2222,
        host_key_path: str = "/etc/gateway/host_key",
        # Client auth
        authorized_keys_path: Optional[str] = None,
        authorized_keys_content: Optional[str] = None,
        accept_any_key: bool = False,
        password_auth: bool = False,
        passwords: Optional[dict] = None,
        # Fixed remote target (required)
        remote_host: Optional[str] = None,
        remote_port: int = 22,
        # Remote host-key verification
        remote_known_hosts: Optional[str] = None,
        remote_ignore_host_key: bool = False,
    ):
        self.host = host
        self.port = port
        self.host_key_path = host_key_path

        self.authorized_keys_path = authorized_keys_path
        self.authorized_keys_content = authorized_keys_content
        self.accept_any_key = accept_any_key
        self.password_auth = password_auth
        self.passwords: dict = passwords or {}

        self.remote_host = remote_host
        self.remote_port = remote_port

        self.remote_known_hosts = remote_known_hosts
        self.remote_ignore_host_key = remote_ignore_host_key

        self._effective_authorized_keys: Optional[str] = None
        self._load_authorized_keys()
        self._validate()

    # ------------------------------------------------------------------
    # Startup validation — fail fast rather than silently misbehave
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        if not self.remote_host:
            raise ConfigError(
                "REMOTE_HOST is not set.  "
                "The gateway requires a fixed remote target — dynamic routing is disabled."
            )
        if not self.remote_host.replace(".", "").replace("-", "").isalnum():
            # Basic sanity: reject obvious injection attempts in the host value
            raise ConfigError(
                f"REMOTE_HOST contains disallowed characters: {self.remote_host!r}"
            )
        if not (1 <= self.remote_port <= 65535):
            raise ConfigError(f"REMOTE_PORT out of range: {self.remote_port}")
        if not (1 <= self.port <= 65535):
            raise ConfigError(f"GATEWAY_PORT out of range: {self.port}")

    # ------------------------------------------------------------------
    # Username validation
    # ------------------------------------------------------------------

    @staticmethod
    def is_valid_username(username: str) -> bool:
        """
        Return True only if ``username`` is a safe Unix-style username.

        Rejects anything containing '@', shell metacharacters, path components,
        or control characters.  Pattern: ``[a-zA-Z0-9._-]{1,64}``
        """
        return bool(_USERNAME_RE.match(username))

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def _load_authorized_keys(self) -> None:
        if self.authorized_keys_content:
            self._effective_authorized_keys = self.authorized_keys_content
        elif self.authorized_keys_path:
            try:
                with open(self.authorized_keys_path) as fh:
                    self._effective_authorized_keys = fh.read()
            except OSError as exc:
                logger.warning(
                    "Cannot read authorized_keys %s: %s", self.authorized_keys_path, exc
                )

    @property
    def effective_authorized_keys(self) -> Optional[str]:
        return self._effective_authorized_keys

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        """Build config entirely from environment variables."""
        raw_passwords = os.environ.get("GATEWAY_PASSWORDS", "")
        passwords: dict = {}
        for pair in raw_passwords.split(","):
            pair = pair.strip()
            if ":" in pair:
                u, p = pair.split(":", 1)
                passwords[u.strip()] = p.strip()

        return cls(
            host=os.environ.get("GATEWAY_HOST", "0.0.0.0"),
            port=int(os.environ.get("GATEWAY_PORT", "2222")),
            host_key_path=os.environ.get("GATEWAY_HOST_KEY_PATH", "/etc/gateway/host_key"),
            authorized_keys_path=os.environ.get("GATEWAY_AUTHORIZED_KEYS_PATH"),
            authorized_keys_content=os.environ.get("GATEWAY_AUTHORIZED_KEYS_CONTENT"),
            accept_any_key=os.environ.get("GATEWAY_ACCEPT_ANY_KEY", "").lower() in ("1", "true", "yes"),
            password_auth=os.environ.get("GATEWAY_PASSWORD_AUTH", "").lower() in ("1", "true", "yes"),
            passwords=passwords,
            remote_host=os.environ.get("REMOTE_HOST"),
            remote_port=int(os.environ.get("REMOTE_PORT", "22")),
            remote_known_hosts=os.environ.get("REMOTE_KNOWN_HOSTS"),
            remote_ignore_host_key=os.environ.get("REMOTE_IGNORE_HOST_KEY", "").lower() in ("1", "true", "yes"),
        )

    @classmethod
    def from_yaml(cls, path: str) -> "GatewayConfig":
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        return cls(**{k: v for k, v in data.items() if not k.startswith("_")})

    def get_remote_destination(self, ssh_username: str) -> tuple:
        """
        Return ``(remote_user, remote_host, remote_port)`` for an authenticated session.

        ``remote_host`` and ``remote_port`` are ALWAYS the fixed configured values —
        clients cannot override them.  ``remote_user`` is the SSH login username,
        which must already have passed ``is_valid_username()`` before this is called.
        """
        return ssh_username, self.remote_host, self.remote_port
