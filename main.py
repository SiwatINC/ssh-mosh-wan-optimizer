#!/usr/bin/env python3
"""
SSH ↔ MOSH WAN Gateway
======================

Exposes an SSH server that local clients connect to; the gateway tunnels
the session to the configured remote SSH server using MOSH, which handles
lossy / high-latency WAN links gracefully.

         Local Client  ──SSH──►  [Gateway]  ──MOSH/UDP──►  Remote SSH Server

Authentication is passed through: the client's SSH agent is forwarded and
used to authenticate to the remote server.  The SSH login username IS the
remote username.  No gateway-owned keys required.

Usage
-----
  # Fixed remote target — loaded from environment:
  REMOTE_HOST=my-server.example.com \\
  GATEWAY_AUTHORIZED_KEYS_PATH=/keys/authorized_keys \\
  python main.py

  # From a YAML config file:
  python main.py --config config.yaml

  # Dynamic routing — no fixed remote:
  GATEWAY_ACCEPT_ANY_KEY=true python main.py
  # Connect: ssh -A -p 2222 "ubuntu@10.0.0.1"@localhost

  # Client connection (always use -A for agent forwarding):
  ssh -A -p 2222 alice@gateway-host
  ssh -A -p 2222 "alice@remote-server"@gateway-host
  ssh -A -p 2222 "alice@remote-server:2222"@gateway-host
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
    p.add_argument("--config", "-c", metavar="FILE",
                   help="Path to YAML config file")
    p.add_argument("--host", metavar="ADDR",
                   help="Bind address (default: 0.0.0.0 / GATEWAY_HOST)")
    p.add_argument("--port", "-p", type=int, metavar="PORT",
                   help="SSH listen port (default: 2222 / GATEWAY_PORT)")
    p.add_argument("--remote-host", metavar="HOST",
                   help="Remote SSH server host (or REMOTE_HOST)")
    p.add_argument("--remote-port", type=int, metavar="PORT",
                   help="Remote SSH port (default: 22 / REMOTE_PORT)")
    p.add_argument("--authorized-keys", metavar="PATH",
                   help="authorized_keys file for client auth (or GATEWAY_AUTHORIZED_KEYS_PATH)")
    p.add_argument("--accept-any-key", action="store_true", default=None,
                   help="Accept any client public key without validation (dev mode)")
    p.add_argument("--remote-known-hosts", metavar="PATH",
                   help="known_hosts file for verifying remote host key (or REMOTE_KNOWN_HOSTS)")
    p.add_argument("--ignore-remote-host-key", action="store_true", default=None,
                   help="Skip remote host-key verification (insecure; or REMOTE_IGNORE_HOST_KEY)")
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

    config = GatewayConfig.from_yaml(args.config) if args.config else GatewayConfig.from_env()

    # CLI overrides
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.remote_host:
        config.default_remote_host = args.remote_host
    if args.remote_port:
        config.default_remote_port = args.remote_port
    if args.authorized_keys:
        config.authorized_keys_path = args.authorized_keys
        config._load_authorized_keys()
    if args.accept_any_key:
        config.accept_any_key = True
    if args.remote_known_hosts:
        config.remote_known_hosts = args.remote_known_hosts
    if args.ignore_remote_host_key:
        config.remote_ignore_host_key = True

    try:
        asyncio.run(run_gateway(config))
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Gateway stopped.")


if __name__ == "__main__":
    main()
