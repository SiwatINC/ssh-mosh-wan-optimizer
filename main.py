#!/usr/bin/env python3
"""
SSH ↔ MOSH WAN Gateway
======================

Exposes an SSH server that local clients connect to; the gateway then
tunnels the session to the configured remote SSH server using MOSH,
which handles lossy / high-latency WAN links gracefully.

         Local Client  ──SSH──►  [Gateway]  ──MOSH/UDP──►  Remote SSH Server

Usage
-----
  # From environment variables (recommended for Docker):
  REMOTE_HOST=my-server.example.com \\
  GATEWAY_SSH_KEY_PATH=/keys/id_ed25519 \\
  GATEWAY_AUTHORIZED_KEYS_PATH=/keys/authorized_keys \\
  python main.py

  # From a YAML config file:
  python main.py --config config.yaml

  # Quick start with dynamic routing (no fixed remote):
  GATEWAY_ACCEPT_ANY_KEY=true python main.py
  # Then: ssh "ubuntu@10.0.0.1"@localhost -p 2222
"""

import argparse
import asyncio
import logging
import sys

from gateway.config import GatewayConfig
from gateway.server import run_gateway


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SSH ↔ MOSH WAN Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--config", "-c",
        metavar="FILE",
        help="Path to YAML config file (overrides environment variables)",
    )
    p.add_argument(
        "--host",
        metavar="ADDR",
        help="Bind address (default: 0.0.0.0 or GATEWAY_HOST env var)",
    )
    p.add_argument(
        "--port", "-p",
        type=int,
        metavar="PORT",
        help="SSH listen port (default: 2222 or GATEWAY_PORT env var)",
    )
    p.add_argument(
        "--remote-host",
        metavar="HOST",
        help="Remote SSH server hostname/IP (or REMOTE_HOST env var)",
    )
    p.add_argument(
        "--remote-port",
        type=int,
        metavar="PORT",
        help="Remote SSH port (default: 22 or REMOTE_PORT env var)",
    )
    p.add_argument(
        "--remote-user",
        metavar="USER",
        help="Remote SSH username (or REMOTE_USER env var)",
    )
    p.add_argument(
        "--ssh-key",
        metavar="PATH",
        help="Private key used by gateway to authenticate to remote (or GATEWAY_SSH_KEY_PATH)",
    )
    p.add_argument(
        "--authorized-keys",
        metavar="PATH",
        help="authorized_keys file for local client auth (or GATEWAY_AUTHORIZED_KEYS_PATH)",
    )
    p.add_argument(
        "--accept-any-key",
        action="store_true",
        default=None,
        help="Accept any client public key without validation (dev mode)",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO)",
    )
    return p


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )
    # Quieten noisy asyncssh internals
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)

    # Load config: YAML file takes precedence over env vars
    if args.config:
        config = GatewayConfig.from_yaml(args.config)
    else:
        config = GatewayConfig.from_env()

    # CLI flags override everything
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.remote_host:
        config.default_remote_host = args.remote_host
    if args.remote_port:
        config.default_remote_port = args.remote_port
    if args.remote_user:
        config.default_remote_user = args.remote_user
    if args.ssh_key:
        config.gateway_ssh_key_path = args.ssh_key
        config._effective_key_path = args.ssh_key
    if args.authorized_keys:
        config.authorized_keys_path = args.authorized_keys
        config._resolve()  # reload keys
    if args.accept_any_key:
        config.accept_any_key = True

    try:
        asyncio.run(run_gateway(config))
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Gateway stopped.")


if __name__ == "__main__":
    main()
