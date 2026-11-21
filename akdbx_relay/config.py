"""Configuration from environment variables (see README for the full list)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"

_PREFIX = "AKDBX_RELAY_"


class ConfigError(ValueError):
    pass


def _get(env: dict[str, str], name: str, default: str) -> str:
    return env.get(_PREFIX + name, default).strip()


def _int(env: dict[str, str], name: str, default: int, minimum: int = 0) -> int:
    raw = _get(env, name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{_PREFIX}{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{_PREFIX}{name} must be at least {minimum}")
    return value


def _float(env: dict[str, str], name: str, default: float, minimum: float = 0.0) -> float:
    raw = _get(env, name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{_PREFIX}{name} must be a number") from exc
    if value < minimum:
        raise ConfigError(f"{_PREFIX}{name} must be at least {minimum}")
    return value


def _hosts(raw: str) -> list[str]:
    return [h.strip() for h in raw.split(",") if h.strip()]


@dataclass
class Config:
    domain: str = "akdbx.link"
    public_hosts: list[str] = field(default_factory=lambda: ["0.0.0.0", "::"])
    public_port: int = 8443
    advertised_port: int = 8443
    control_host: str = "127.0.0.1"
    control_port: int = 8771
    state_path: str = "/var/lib/akdbx-relay/relay.sqlite3"

    acme_directory: str = LE_PRODUCTION
    acme_account_key_file: str = "/var/lib/akdbx-relay/acme-account.pem"
    acme_email: str = ""
    acme_ca_bundle: str = ""
    acme_timeout: float = 60.0
    dns_propagation_seconds: float = 10.0
    cloudflare_api: str = CLOUDFLARE_API
    cloudflare_token: str = field(default="", repr=False)
    cloudflare_zone_id: str = ""

    cert_budget: int = 40
    cert_hard_limit: int = 48
    certs_per_broker_week: int = 5
    max_concurrent_issuance: int = 2
    registrations_per_ip_day: int = 5
    trusted_proxy_ips: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])

    max_streams_per_broker: int = 64
    max_streams_total: int = 2048
    max_pending_handshakes: int = 1024
    conn_rate_per_ip: float = 10.0
    conn_burst_per_ip: int = 20
    client_hello_timeout: float = 5.0
    client_hello_max_bytes: int = 16384
    stream_open_timeout: float = 10.0
    stream_idle_timeout: float = 300.0
    control_ping_interval: float = 30.0
    control_pong_timeout: float = 60.0
    ws_ping_interval: float = 30.0

    log_level: str = "INFO"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        d = cls()
        acme_dir = _get(env, "ACME_DIRECTORY", "production")
        if acme_dir == "production":
            acme_dir = LE_PRODUCTION
        elif acme_dir == "staging":
            acme_dir = LE_STAGING
        public_port = _int(env, "PUBLIC_PORT", d.public_port)
        cfg = cls(
            domain=_get(env, "DOMAIN", d.domain).lower().rstrip("."),
            public_hosts=_hosts(_get(env, "PUBLIC_HOSTS", ",".join(d.public_hosts))),
            public_port=public_port,
            advertised_port=_int(env, "ADVERTISED_PORT", public_port or d.advertised_port, 1),
            control_host=_get(env, "CONTROL_HOST", d.control_host),
            control_port=_int(env, "CONTROL_PORT", d.control_port),
            state_path=_get(env, "STATE_PATH", d.state_path),
            acme_directory=acme_dir,
            acme_account_key_file=_get(env, "ACME_ACCOUNT_KEY_FILE", d.acme_account_key_file),
            acme_email=_get(env, "ACME_EMAIL", ""),
            acme_ca_bundle=_get(env, "ACME_CA_BUNDLE", ""),
            acme_timeout=_float(env, "ACME_TIMEOUT", d.acme_timeout, 1.0),
            dns_propagation_seconds=_float(env, "DNS_PROPAGATION_SECONDS", d.dns_propagation_seconds),
            cloudflare_api=_get(env, "CLOUDFLARE_API", d.cloudflare_api).rstrip("/"),
            cloudflare_token=_get(env, "CLOUDFLARE_API_TOKEN", ""),
            cloudflare_zone_id=_get(env, "CLOUDFLARE_ZONE_ID", ""),
            cert_budget=_int(env, "CERT_BUDGET", d.cert_budget, 1),
            cert_hard_limit=_int(env, "CERT_HARD_LIMIT", d.cert_hard_limit, 1),
            certs_per_broker_week=_int(env, "CERTS_PER_BROKER_WEEK", d.certs_per_broker_week, 1),
            max_concurrent_issuance=_int(env, "MAX_CONCURRENT_ISSUANCE", d.max_concurrent_issuance, 1),
            registrations_per_ip_day=_int(env, "REGISTRATIONS_PER_IP_DAY", d.registrations_per_ip_day, 1),
            trusted_proxy_ips=_hosts(_get(env, "TRUSTED_PROXY_IPS", ",".join(d.trusted_proxy_ips))),
            max_streams_per_broker=_int(env, "MAX_STREAMS_PER_BROKER", d.max_streams_per_broker, 1),
            max_streams_total=_int(env, "MAX_STREAMS_TOTAL", d.max_streams_total, 1),
            max_pending_handshakes=_int(env, "MAX_PENDING_HANDSHAKES", d.max_pending_handshakes, 1),
            conn_rate_per_ip=_float(env, "CONN_RATE_PER_IP", d.conn_rate_per_ip, 0.1),
            conn_burst_per_ip=_int(env, "CONN_BURST_PER_IP", d.conn_burst_per_ip, 1),
            client_hello_timeout=_float(env, "CLIENT_HELLO_TIMEOUT", d.client_hello_timeout, 0.1),
            client_hello_max_bytes=_int(env, "CLIENT_HELLO_MAX_BYTES", d.client_hello_max_bytes, 512),
            stream_open_timeout=_float(env, "STREAM_OPEN_TIMEOUT", d.stream_open_timeout, 0.1),
            stream_idle_timeout=_float(env, "STREAM_IDLE_TIMEOUT", d.stream_idle_timeout, 1.0),
            control_ping_interval=_float(env, "CONTROL_PING_INTERVAL", d.control_ping_interval, 0.1),
            control_pong_timeout=_float(env, "CONTROL_PONG_TIMEOUT", d.control_pong_timeout, 0.1),
            ws_ping_interval=_float(env, "WS_PING_INTERVAL", d.ws_ping_interval, 0.1),
            log_level=_get(env, "LOG_LEVEL", d.log_level).upper(),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.domain or "." not in self.domain:
            raise ConfigError("AKDBX_RELAY_DOMAIN must be a domain name")
        if self.cert_hard_limit < self.cert_budget:
            raise ConfigError("AKDBX_RELAY_CERT_HARD_LIMIT must be at least AKDBX_RELAY_CERT_BUDGET")
        if self.client_hello_max_bytes > 65536:
            raise ConfigError("AKDBX_RELAY_CLIENT_HELLO_MAX_BYTES must be at most 65536")

    @property
    def issuance_configured(self) -> bool:
        return bool(self.cloudflare_token and self.cloudflare_zone_id and self.acme_directory)
