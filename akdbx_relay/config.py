"""Relay configuration from environment variables (``AKDBX_RELAY_*``)."""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from .names import RESERVED_LABELS

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_ALIASES = {"production": LE_PRODUCTION, "staging": LE_STAGING}

PREFIX = "AKDBX_RELAY_"


class ConfigError(ValueError):
    pass


def parse_listen(value: str) -> tuple[tuple[str, int], ...]:
    """Parse ``host:port,[v6]:port`` into ``((host, port), ...)``."""
    out: list[tuple[str, int]] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("["):
            host, sep, port = item[1:].partition("]:")
            if not sep:
                raise ConfigError(f"bad listen address: {item!r}")
        else:
            host, sep, port = item.rpartition(":")
            if not sep or ":" in host:
                raise ConfigError(f"bad listen address: {item!r} (write IPv6 as [addr]:port)")
        try:
            port_number = int(port)
        except ValueError:
            raise ConfigError(f"bad port in listen address: {item!r}") from None
        if not 0 <= port_number <= 65535:
            raise ConfigError(f"bad port in listen address: {item!r}")
        out.append((host, port_number))
    if not out:
        raise ConfigError("empty listen address list")
    return tuple(out)


@dataclass(frozen=True)
class Config:
    domain: str = "akdbx.link"
    public_listen: tuple[tuple[str, int], ...] = (("0.0.0.0", 8443), ("::", 8443))
    public_port: int = 8443
    control_listen: tuple[tuple[str, int], ...] = (("127.0.0.1", 8771),)
    state_db: str = "/var/lib/akdbx-relay/relay.sqlite3"

    acme_directory: str = LE_PRODUCTION
    acme_account_key_file: str = "/var/lib/akdbx-relay/acme-account-key.pem"
    acme_email: str = ""
    acme_timeout: float = 90.0
    dns_propagation_seconds: float = 10.0
    cloudflare_api_token: str = field(default="", repr=False)
    cloudflare_zone_id: str = ""
    cloudflare_api_base: str = "https://api.cloudflare.com/client/v4"

    cert_budget: int = 40
    cert_budget_window: float = 7 * 86400.0
    certs_per_broker_per_window: int = 3
    issuance_concurrency: int = 2
    registrations_per_ip_per_day: int = 5
    unclaimed_broker_days: float = 7.0

    max_streams_per_broker: int = 64
    max_streams_total: int = 2048
    max_connections_per_ip: int = 128
    connections_per_ip_per_second: float = 10.0
    clienthello_timeout: float = 5.0
    clienthello_max_bytes: int = 16384
    stream_open_timeout: float = 10.0
    stream_idle_timeout: float = 300.0
    stream_keepalive_interval: float = 30.0
    control_ping_interval: float = 30.0
    control_ping_timeout: float = 60.0

    trusted_proxies: frozenset[str] = frozenset({"127.0.0.1", "::1"})
    reserved_labels: frozenset[str] = RESERVED_LABELS
    log_level: str = "INFO"

    def replace(self, **changes) -> "Config":
        return dataclasses.replace(self, **changes)

    def summary(self) -> dict[str, object]:
        """Non-secret view of the configuration."""
        out: dict[str, object] = {}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if f.name == "cloudflare_api_token":
                value = "set" if value else "missing"
            elif isinstance(value, frozenset):
                value = sorted(value)
            out[f.name] = value
        return out

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        base = cls()
        kwargs: dict[str, object] = {}

        def get(name: str) -> str | None:
            value = env.get(PREFIX + name)
            return None if value is None or value.strip() == "" else value.strip()

        def num(name: str, attr: str, kind: type, minimum: float = 0) -> None:
            raw = get(name)
            if raw is None:
                return
            try:
                value = kind(raw)
            except ValueError:
                raise ConfigError(f"{PREFIX}{name} must be a number") from None
            if value < minimum:
                raise ConfigError(f"{PREFIX}{name} must be at least {minimum}")
            kwargs[attr] = value

        if (v := get("DOMAIN")) is not None:
            kwargs["domain"] = v.lower().strip(".")
        if (v := get("PUBLIC_LISTEN")) is not None:
            kwargs["public_listen"] = parse_listen(v)
        if (v := get("CONTROL_LISTEN")) is not None:
            kwargs["control_listen"] = parse_listen(v)
        num("PUBLIC_PORT", "public_port", int, 1)
        if (v := get("STATE_DB")) is not None:
            kwargs["state_db"] = v
        if (v := get("ACME_DIRECTORY")) is not None:
            kwargs["acme_directory"] = ACME_ALIASES.get(v.lower(), v)
        if (v := get("ACME_ACCOUNT_KEY_FILE")) is not None:
            kwargs["acme_account_key_file"] = v
        if (v := get("ACME_EMAIL")) is not None:
            kwargs["acme_email"] = v
        num("ACME_TIMEOUT_SECONDS", "acme_timeout", float, 5)
        num("DNS_PROPAGATION_SECONDS", "dns_propagation_seconds", float, 0)
        if (v := get("CLOUDFLARE_API_TOKEN")) is not None:
            kwargs["cloudflare_api_token"] = v
        if (v := get("CLOUDFLARE_ZONE_ID")) is not None:
            kwargs["cloudflare_zone_id"] = v
        if (v := get("CLOUDFLARE_API_BASE")) is not None:
            kwargs["cloudflare_api_base"] = v.rstrip("/")
        num("CERT_BUDGET", "cert_budget", int, 0)
        num("CERT_BUDGET_WINDOW_SECONDS", "cert_budget_window", float, 1)
        num("CERTS_PER_BROKER_PER_WINDOW", "certs_per_broker_per_window", int, 1)
        num("ISSUANCE_CONCURRENCY", "issuance_concurrency", int, 1)
        num("REGISTRATIONS_PER_IP_PER_DAY", "registrations_per_ip_per_day", int, 0)
        num("UNCLAIMED_BROKER_DAYS", "unclaimed_broker_days", float, 0)
        num("MAX_STREAMS_PER_BROKER", "max_streams_per_broker", int, 1)
        num("MAX_STREAMS_TOTAL", "max_streams_total", int, 1)
        num("MAX_CONNECTIONS_PER_IP", "max_connections_per_ip", int, 1)
        num("CONNECTIONS_PER_IP_PER_SECOND", "connections_per_ip_per_second", float, 0.01)
        num("CLIENTHELLO_TIMEOUT_SECONDS", "clienthello_timeout", float, 0.1)
        num("CLIENTHELLO_MAX_BYTES", "clienthello_max_bytes", int, 512)
        num("STREAM_OPEN_TIMEOUT_SECONDS", "stream_open_timeout", float, 0.1)
        num("STREAM_IDLE_TIMEOUT_SECONDS", "stream_idle_timeout", float, 1)
        num("STREAM_KEEPALIVE_SECONDS", "stream_keepalive_interval", float, 1)
        num("CONTROL_PING_INTERVAL_SECONDS", "control_ping_interval", float, 0.1)
        num("CONTROL_PING_TIMEOUT_SECONDS", "control_ping_timeout", float, 0.1)
        if (v := get("TRUSTED_PROXIES")) is not None:
            kwargs["trusted_proxies"] = frozenset(p.strip() for p in v.split(",") if p.strip())
        elif PREFIX + "TRUSTED_PROXIES" in env:  # set to empty: trust no proxy header
            kwargs["trusted_proxies"] = frozenset()
        if (v := get("RESERVED_LABELS")) is not None:
            extra = {p.strip().lower() for p in v.split(",") if p.strip()}
            kwargs["reserved_labels"] = RESERVED_LABELS | frozenset(extra)
        if (v := get("LOG_LEVEL")) is not None:
            kwargs["log_level"] = v.upper()

        cfg = dataclasses.replace(base, **kwargs)
        if cfg.control_ping_timeout < cfg.control_ping_interval:
            raise ConfigError("CONTROL_PING_TIMEOUT_SECONDS must be at least the ping interval")
        return cfg


def load_env_file(path: str) -> dict[str, str]:
    """Read a systemd-style ``KEY=VALUE`` file (no shell expansion)."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            out[key] = value
    return out
