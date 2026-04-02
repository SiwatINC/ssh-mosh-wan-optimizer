"""Configuration loading from environment variables or YAML."""

import logging
import os
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


class GatewayConfig:
    """
    All settings for the SSH↔MOSH gateway.

    Client → Gateway authentication
    --------------------------------
    GATEWAY_AUTHORIZED_KEYS_PATH   Path to an authorized_keys file
    GATEWAY_AUTHORIZED_KEYS_CONTENT Raw authorized_keys text (newline-separated)
    GATEWAY_ACCEPT_ANY_KEY         "true" to accept any client public key (dev/trusted LAN only)
    GATEWAY_PASSWORD_AUTH          "true" to also allow password authentication
    GATEWAY_PASSWORDS              Comma-separated user:password pairs, e.g. "alice:s3cr3t,bob:pass"

    Gateway → Remote authentication (agent pass-through)
    -----------------------------------------------------
    Authentication is passed through from the local SSH client via SSH agent
    forwarding.  Connect with:  ssh -A user@gateway -p 2222

    The SSH username used to connect to the gateway becomes the remote username.
    Dynamic host: ssh -A "user@remote-host"@gateway -p 2222

    SSH server settings
    -------------------
    GATEWAY_HOST                   Bind address (default: 0.0.0.0)
    GATEWAY_PORT                   SSH listen port (default: 2222)
    GATEWAY_HOST_KEY_PATH          Server host key path (auto-generated if missing)

    Remote MOSH target
    ------------------
    REMOTE_HOST                    Default remote host to MOSH into (required unless using
                                   dynamic routing via "user@host" SSH usernames)
    REMOTE_PORT                    Default remote SSH port (default: 22)
    REMOTE_KNOWN_HOSTS             Path to a known_hosts file for verifying the remote host key.
                                   Defaults to the system known_hosts (~/.ssh/known_hosts).
    REMOTE_IGNORE_HOST_KEY         "true" to skip remote host-key verification (insecure)
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
        # Remote target
        default_remote_host: Optional[str] = None,
        default_remote_port: int = 22,
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

        self.default_remote_host = default_remote_host
        self.default_remote_port = default_remote_port

        self.remote_known_hosts = remote_known_hosts
        self.remote_ignore_host_key = remote_ignore_host_key

        self._effective_authorized_keys: Optional[str] = None
        self._load_authorized_keys()

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
                logger.warning("Cannot read authorized_keys %s: %s", self.authorized_keys_path, exc)

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
            default_remote_host=os.environ.get("REMOTE_HOST"),
            default_remote_port=int(os.environ.get("REMOTE_PORT", "22")),
            remote_known_hosts=os.environ.get("REMOTE_KNOWN_HOSTS"),
            remote_ignore_host_key=os.environ.get("REMOTE_IGNORE_HOST_KEY", "").lower() in ("1", "true", "yes"),
        )

    @classmethod
    def from_yaml(cls, path: str) -> "GatewayConfig":
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        return cls(**{k: v for k, v in data.items() if not k.startswith("_")})

    def parse_destination(self, ssh_username: str) -> tuple:
        """
        Derive ``(remote_user, remote_host, remote_port)`` from the SSH login username.

        The SSH username IS the remote username.  Supported formats:

          alice               → alice  @  REMOTE_HOST  :  REMOTE_PORT
          alice@10.0.0.1      → alice  @  10.0.0.1     :  REMOTE_PORT
          alice@10.0.0.1:22   → alice  @  10.0.0.1     :  22
        """
        remote_user = ssh_username
        remote_host = self.default_remote_host
        remote_port = self.default_remote_port

        if "@" in ssh_username:
            user_part, host_part = ssh_username.split("@", 1)
            remote_user = user_part
            if ":" in host_part:
                h, p = host_part.rsplit(":", 1)
                remote_host = h
                try:
                    remote_port = int(p)
                except ValueError:
                    pass
            else:
                remote_host = host_part

        if not remote_host:
            raise ValueError(
                "No remote host configured.  Set REMOTE_HOST or use SSH username "
                "format 'remoteuser@remotehost'."
            )
        if not remote_user:
            raise ValueError("Could not determine remote username from SSH login.")

        return remote_user, remote_host, remote_port
