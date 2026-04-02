# ssh-mosh-wan-optimizer

A gateway service that accepts SSH connections from local clients and tunnels them to a remote SSH server over [MOSH](https://mosh.org/), providing resilience against packet loss and high latency on WAN links.

```
Local Client ──SSH──► [Gateway] ──MOSH/UDP──► Remote SSH Server
```

MOSH uses UDP with its State Synchronization Protocol (SSP), handling roaming, packet loss, and high-latency paths far better than a plain SSH-over-SSH tunnel.

---

## Security model

- The remote target (`REMOTE_HOST`) is **fixed at startup** — clients cannot redirect to arbitrary hosts.
- SSH usernames are validated to `[a-zA-Z0-9._-]{1,64}` and rejected immediately on mismatch.
- Authentication to the remote is **passed through** via the client's forwarded SSH agent — the gateway holds no credentials of its own.
- Optionally pre-screen clients with a local `authorized_keys` file; if omitted, the remote server's own `authorized_keys` is the effective auth gate.

---

## Quick start

### Docker Compose

```yaml
# docker-compose.yml
environment:
  REMOTE_HOST: "my-server.example.com"
```

```bash
docker compose up -d
```

Connect from your local machine:

```bash
ssh -p 2222 alice@gateway-host
```

### Run directly

```bash
pip install -r requirements.txt
REMOTE_HOST=my-server.example.com python main.py
```

---

## Configuration

All settings can be provided as environment variables, a YAML file (`--config config.yaml`), or CLI flags. See [`config.yaml.example`](config.yaml.example) for a fully annotated example.

### Remote target

| Variable | Default | Description |
|---|---|---|
| `REMOTE_HOST` | — | **Required.** The only host clients can reach through this gateway. |
| `REMOTE_PORT` | `22` | Remote SSH port. |
| `REMOTE_KNOWN_HOSTS` | system | Path to a `known_hosts` file to verify the remote host key. |
| `REMOTE_IGNORE_HOST_KEY` | `false` | Skip remote host-key verification *(insecure)*. |

### Client → Gateway authentication

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_AUTHORIZED_KEYS_PATH` | — | Path to an `authorized_keys` file. If unset, any key is accepted and the remote is the auth gate. |
| `GATEWAY_AUTHORIZED_KEYS_CONTENT` | — | Inline `authorized_keys` text (alternative to the path). |
| `GATEWAY_PASSWORD_AUTH` | `false` | Also accept password authentication. |
| `GATEWAY_PASSWORDS` | — | Comma-separated `user:password` pairs, e.g. `alice:s3cr3t,bob:pass`. |
| `GATEWAY_ACCEPT_ANY_KEY` | `false` | Accept any client key without validation *(dev / trusted LAN only)*. |

### Gateway → Remote authentication

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_SSH_KEY_PATH` | — | Path to the private key used to authenticate to the remote server. |
| `GATEWAY_SSH_KEY_CONTENT` | — | Base64-encoded private key (alternative to the file path). |

### SSH server

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_HOST` | `0.0.0.0` | Bind address. |
| `GATEWAY_PORT` | `2222` | SSH listen port. |
| `GATEWAY_HOST_KEY_PATH` | `/etc/gateway/host_key` | Server host key (auto-generated as ed25519 if missing). |

---

## Authentication flow

```
1. Client:   ssh -p 2222 alice@gateway
             │
             │  SSH public-key auth
             ▼
2. Gateway:  Validates key against GATEWAY_AUTHORIZED_KEYS_PATH
             (or accepts any key and delegates to remote if unset)
             │
             │  Gateway uses its own key (GATEWAY_SSH_KEY_PATH)
             ▼
3. Gateway:  asyncssh connects to REMOTE_HOST as user "alice"
             using the gateway's private key
             │
             │  mosh-server started on remote via SSH
             ▼
4. Gateway:  mosh-client subprocess connects to remote over MOSH/UDP
             │
             │  PTY I/O bridged back over SSH to local client
             ▼
5. Client:   Interactive session, MOSH-resilient over the WAN leg
```

The gateway holds one key for the remote; clients need no special flags. The SSH login username becomes the remote username.

---

## Requirements

**Gateway host:** Python 3.11+, `mosh-client`, `openssh-client`

**Remote server:** `mosh-server` installed and reachable via SSH

**Client:** Any standard SSH client

---

## Docker image

Images are published to `ghcr.io/siwatinc/ssh-mosh-wan-optimizer` via GitHub Actions on every push to `main` and on semver tags. Multi-arch: `linux/amd64` and `linux/arm64`.

```bash
docker pull ghcr.io/siwatinc/ssh-mosh-wan-optimizer:latest
```

Mount your key material into `/keys/`:

```
keys/
  id_ed25519        ← gateway's private key (must be in authorized_keys on remote)
  authorized_keys   ← (optional) public keys of clients allowed to connect to the gateway
  known_hosts       ← (optional) pin the remote server's host key
```
