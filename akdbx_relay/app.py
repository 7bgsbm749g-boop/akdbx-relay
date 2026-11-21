"""Command-line entry point: `akdbx-relay`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys

from . import __version__
from .cloudflare import CloudflareDNS
from .config import Config, ConfigError
from .issuer import ACMEIssuer
from .relay import Relay
from .store import Store

log = logging.getLogger("akdbx_relay")


def load_env_file(path: str) -> dict[str, str]:
    """Read KEY=VALUE lines (systemd EnvironmentFile style, no expansion)."""
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values


def build(cfg: Config) -> Relay:
    store = Store(cfg.state_path)
    issuer = None
    if cfg.issuance_configured:
        dns = CloudflareDNS(cfg.cloudflare_api, cfg.cloudflare_token, cfg.cloudflare_zone_id)
        issuer = ACMEIssuer(cfg, store, dns)
    else:
        log.warning("certificate issuance is not configured (Cloudflare token or zone id missing)")
    return Relay(cfg, store, issuer)


async def serve(cfg: Config) -> None:
    relay = build(cfg)
    await relay.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - Windows
            pass
    await stop.wait()
    log.info("shutting down")
    await relay.stop()
    relay.store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="akdbx-relay", description=__doc__)
    parser.add_argument("--env-file", help="read AKDBX_RELAY_* settings from this file first")
    parser.add_argument("--check-config", action="store_true", help="validate the configuration and exit")
    parser.add_argument("--version", action="version", version=f"akdbx-relay {__version__}")
    args = parser.parse_args(argv)

    env = dict(os.environ)
    if args.env_file:
        file_env = load_env_file(args.env_file)
        file_env.update({k: v for k, v in env.items() if k.startswith("AKDBX_RELAY_")})
        env.update(file_env)
    try:
        cfg = Config.from_env(env)
    except ConfigError as exc:
        print(f"akdbx-relay: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=getattr(logging, cfg.log_level, logging.INFO),
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.check_config:
        print(f"configuration OK; certificate issuance {'on' if cfg.issuance_configured else 'off'}")
        return 0
    asyncio.run(serve(cfg))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
