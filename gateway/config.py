"""Configuration loading from environment variables or YAML."""

import base64
import logging
import os
import stat
import tempfile
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


class GatewayConfig:
    """
    All settings for the SSH↔MOSH gateway.

    Priority: explicit kwargs > environment variables > defaults.

    Client → Gateway authentication
    --------------------------------
    GATEWAY_AUTHORIZED_KEYS_PATH   Path to an authorized_keys file
    GATEWAY_AUTHORIZED_KEYS_CONTENT Raw authorized_keys text (newline-separated)
    GATEWAY_ACCEPT_ANY_KEY         "true" to accept any client public key (dev/trusted LAN only)
    GATEWAY_PASSWORD_AUTH          "true" to also allow password authentication
    GATEWAY_PASSWORDS              Comma-separated user:password pairs, e.g. "alice:s3cr3t,bob:pass"

    Gateway → Remote authentication
    --------------------------------
    GATEWAY_SSH_KEY_PATH           Path to the private key used when SSHing to remote
    GATEWAY_SSH_KEY_CONTENT        Base64-encoded private key (alternative to file path)

    SSH server settings
    -------------------
    GATEWAY_HOST                   Bind address (default: 0.0.0.0)
    GATEWAY_PORT                   SSH listen port (default: 2222)
    GATEWAY_HOST_KEY_PATH          Server host key path (auto-generated if missing)

    Remote MOSH target
    ------------------
    REMOTE_HOST                    Default remote host to MOSH into
    REMOTE_PORT                    Default remote SSH port (default: 22)
    REMOTE_USER                    Default remote username (falls back to SSH login name)
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
        default_remote_user: Optional[str] = None,
        # Gateway→Remote key
        gateway_ssh_key_path: Optional[str] = None,
        gateway_ssh_key_content: Optional[str] = None,
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
        self.default_remote_user = default_remote_user

        self.gateway_ssh_key_path = gateway_ssh_key_path
        self.gateway_ssh_key_content = gateway_ssh_key_content

        # Resolved at init time
        self._effective_key_path: Optional[str] = None
        self._effective_authorized_keys: Optional[str] = None
        self._tmp_key_file: Optional[str] = None

        self._resolve()

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def _resolve(self):
        """Materialise key content → temp file, load authorized_keys text."""
        # Gateway→Remote SSH key
        if self.gateway_ssh_key_content and not self.gateway_ssh_key_path:
            key_bytes = base64.b64decode(self.gateway_ssh_key_content)
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_gw_key", mode="wb")
            tmp.write(key_bytes)
            tmp.close()
            os.chmod(tmp.name, stat.S_IRUSR | stat.S_IWUSR)
            self._tmp_key_file = tmp.name
            self._effective_key_path = tmp.name
        else:
            self._effective_key_path = self.gateway_ssh_key_path

        # Authorized keys
        if self.authorized_keys_content:
            self._effective_authorized_keys = self.authorized_keys_content
        elif self.authorized_keys_path:
            try:
                with open(self.authorized_keys_path) as fh:
                    self._effective_authorized_keys = fh.read()
            except OSError as exc:
                logger.warning("Cannot read authorized_keys %s: %s", self.authorized_keys_path, exc)

    @property
    def effective_ssh_key_path(self) -> Optional[str]:
        return self._effective_key_path

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
            default_remote_user=os.environ.get("REMOTE_USER"),
            gateway_ssh_key_path=os.environ.get("GATEWAY_SSH_KEY_PATH"),
            gateway_ssh_key_content=os.environ.get("GATEWAY_SSH_KEY_CONTENT"),
        )

    @classmethod
    def from_yaml(cls, path: str) -> "GatewayConfig":
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        # Strip leading underscores (private fields) just in case
        return cls(**{k: v for k, v in data.items() if not k.startswith("_")})

    def parse_destination(self, ssh_username: str) -> tuple:
        """
        Derive (remote_user, remote_host, remote_port) from the SSH login username.

        Supported formats:
          alice               → (alice or REMOTE_USER,  REMOTE_HOST, REMOTE_PORT)
          alice@10.0.0.1      → (alice,                 10.0.0.1,   REMOTE_PORT)
          alice@10.0.0.1:22   → (alice,                 10.0.0.1,   22)
        """
        remote_user = self.default_remote_user or ssh_username
        remote_host = self.default_remote_host
        remote_port = self.default_remote_port

        if "@" in ssh_username:
            user_part, host_part = ssh_username.split("@", 1)
            remote_user = user_part or remote_user
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
                "No remote host configured. Set REMOTE_HOST or use SSH username "
                "format 'remoteuser@remotehost'."
            )

        return remote_user, remote_host, remote_port
