#!/usr/bin/env python3
"""
SSH ↔ MOSH WAN Gateway
======================

Exposes an SSH server that local clients connect to; the gateway tunnels
the session to a single, fixed remote SSH server using MOSH, which handles
lossy / high-latency WAN links gracefully.

         Local Client  ──SSH──►  [Gateway]  ──MOSH/UDP──►  Remote SSH Server

Security model
--------------
  • Remote target is FIXED at startup (REMOTE_HOST).  Clients cannot
    redirect to arbitrary hosts.
  • SSH usernames are validated (alphanumeric + . _ - , max 64 chars).
  • Authentication to the remote is passed through via the client's SSH agent.

Usage
-----
  REMOTE_HOST=my-server.example.com \\
  GATEWAY_AUTHORIZED_KEYS_PATH=/keys/authorized_keys \\
  python main.py

  # Or from a YAML config file:
  python main.py --config config.yaml

  # Client connection (always use -A to forward your agent):
  ssh -A -p 2222 alice@gateway-host
"""

import asyncio
import logging
import sys

import argparse

from gateway.config import GatewayConfig, ConfigError
from gateway.server import run_gateway


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SSH ↔ MOSH WAN Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--config", "-c", metavar="FILE",
                   help="Path to YAML config file")
    p.add_argument("--host", metavar="ADDR",
                   help="Bind address (default: 0.0.0.0 / GATEWAY_HOST)")
    p.add_argument("--port", "-p", type=int, metavar="PORT",
                   help="SSH listen port (default: 2222 / GATEWAY_PORT)")
    p.add_argument("--remote-host", metavar="HOST",
                   help="Fixed remote SSH server hostname/IP (or REMOTE_HOST)")
    p.add_argument("--remote-port", type=int, metavar="PORT",
                   help="Remote SSH port (default: 22 / REMOTE_PORT)")
    p.add_argument("--authorized-keys", metavar="PATH",
                   help="authorized_keys file for client auth (or GATEWAY_AUTHORIZED_KEYS_PATH)")
    p.add_argument("--accept-any-key", action="store_true", default=None,
                   help="Accept any client public key without validation (dev mode only)")
    p.add_argument("--remote-known-hosts", metavar="PATH",
                   help="known_hosts file for verifying remote host key (or REMOTE_KNOWN_HOSTS)")
    p.add_argument("--ignore-remote-host-key", action="store_true", default=None,
                   help="Skip remote host-key verification (insecure)")
    p.add_argument("--log-level",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   default="INFO",
                   help="Logging verbosity (default: INFO)")
    return p


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)

    log = logging.getLogger(__name__)

    try:
        config = GatewayConfig.from_yaml(args.config) if args.config else GatewayConfig.from_env()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(1)

    # CLI overrides (re-validate after any change)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.remote_host:
        config.remote_host = args.remote_host
    if args.remote_port:
        config.remote_port = args.remote_port
    if args.authorized_keys:
        config.authorized_keys_path = args.authorized_keys
        config._load_authorized_keys()
    if args.accept_any_key:
        config.accept_any_key = True
    if args.remote_known_hosts:
        config.remote_known_hosts = args.remote_known_hosts
    if args.ignore_remote_host_key:
        config.remote_ignore_host_key = True

    # Re-validate after CLI overrides
    try:
        config._validate()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(1)

    try:
        asyncio.run(run_gateway(config))
    except KeyboardInterrupt:
        log.info("Gateway stopped.")


if __name__ == "__main__":
    main()
