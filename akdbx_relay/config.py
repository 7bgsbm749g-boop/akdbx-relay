"""Configuration from environment variables (see README for the full list)."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

from .names import broker_id_from_host

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"

_PREFIX = "AKDBX_RELAY_"
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# Settings that older drafts used. The control API no longer runs behind a
# proxy, so a leftover value is a configuration mistake, not something to ignore.
_REMOVED = {
    "CONTROL_HOST": "the control API is served on the public port; use AKDBX_RELAY_HEALTH_HOST",
    "CONTROL_PORT": "the control API is served on the public port; use AKDBX_RELAY_HEALTH_PORT",
    "TRUSTED_PROXY_IPS": "the relay trusts no proxy header; rate limits use the TCP peer address",
}


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


def _listen(raw: str) -> list[tuple[str, int]]:
    """Parse ``HOST:PORT,[V6]:PORT`` into (host, port) pairs for extra public listeners."""
    out: list[tuple[str, int]] = []
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        if item.startswith("["):
            host, sep, port = item[1:].partition("]:")
        else:
            host, sep, port = item.rpartition(":")
        try:
            ipaddress.ip_address(host)
            number = int(port)
        except ValueError:
            raise ConfigError(f"{_PREFIX}PUBLIC_EXTRA_LISTEN: {item!r} is not IP:PORT or [IPv6]:PORT") from None
        if not sep or not 1 <= number <= 65535:
            raise ConfigError(f"{_PREFIX}PUBLIC_EXTRA_LISTEN: {item!r} is not IP:PORT or [IPv6]:PORT")
        out.append((host, number))
    return out


def _is_hostname(name: str) -> bool:
    return 1 <= len(name) <= 253 and all(_LABEL.match(label) for label in name.split("."))


@dataclass
class Config:
    domain: str = "akdbx.link"
    public_hosts: list[str] = field(default_factory=lambda: ["0.0.0.0", "::"])
    public_port: int = 8443
    advertised_port: int = 8443
    # Extra public listeners, for example the old port while brokers move to a
    # new one. Each is an (IP address, port) pair with the same behavior.
    public_extra_listen: list[tuple[str, int]] = field(default_factory=list)
    # The control API is served on the public port to TLS connections whose
    # SNI is this name; the relay terminates them with its own certificate.
    control_hostname: str = ""
    # Operator-supplied certificate chain and key for control_hostname. When
    # both are empty, the relay obtains and renews its own certificate through
    # ACME and keeps it in the state directory.
    control_cert_file: str = ""
    control_key_file: str = field(default="", repr=False)
    # Plain-HTTP listener for GET /api/v1/health only, loopback addresses only.
    # An empty health_host disables it.
    health_host: str = "127.0.0.1"
    health_port: int = 8771
    state_path: str = "/var/lib/akdbx-relay/relay.sqlite3"

    acme_directory: str = LE_PRODUCTION
    acme_account_key_file: str = "/var/lib/akdbx-relay/acme-account.pem"
    acme_email: str = ""
    acme_ca_bundle: str = ""
    acme_timeout: float = 60.0
    dns_propagation_seconds: float = 10.0
    # One deadline for a certificate request: queue wait plus the ACME order.
    certificate_deadline: float = 90.0
    cloudflare_api: str = CLOUDFLARE_API
    cloudflare_token: str = field(default="", repr=False)
    cloudflare_zone_id: str = ""

    cert_budget: int = 40
    cert_hard_limit: int = 48
    certs_per_broker_week: int = 5
    max_concurrent_issuance: int = 2
    registrations_per_ip_day: int = 5

    max_streams_per_broker: int = 64
    max_streams_total: int = 2048
    max_pending_handshakes: int = 1024
    max_handshakes_per_ip: int = 8
    max_streams_per_ip: int = 16
    max_control_connections: int = 4096
    max_control_connections_per_ip: int = 96
    conn_rate_per_ip: float = 10.0
    conn_burst_per_ip: int = 20
    # New connections to the control host name per address (brokers' control
    # and stream WebSockets). The burst lets one broker open
    # max_streams_per_broker streams at once.
    control_conn_rate_per_ip: float = 20.0
    control_conn_burst_per_ip: int = 96
    client_hello_timeout: float = 5.0
    client_hello_max_bytes: int = 16384
    stream_open_timeout: float = 10.0
    stream_first_byte_timeout: float = 10.0
    stream_idle_timeout: float = 300.0
    control_ping_interval: float = 30.0
    control_pong_timeout: float = 60.0
    ws_ping_interval: float = 30.0

    log_level: str = "INFO"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        for name, why in _REMOVED.items():
            if (_PREFIX + name) in env:
                raise ConfigError(f"{_PREFIX}{name} is no longer supported: {why}")
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
            public_extra_listen=_listen(_get(env, "PUBLIC_EXTRA_LISTEN", "")),
            control_hostname=_get(env, "CONTROL_HOSTNAME", "").lower().rstrip("."),
            control_cert_file=_get(env, "CONTROL_CERT_FILE", ""),
            control_key_file=_get(env, "CONTROL_KEY_FILE", ""),
            health_host=_get(env, "HEALTH_HOST", d.health_host),
            health_port=_int(env, "HEALTH_PORT", d.health_port),
            state_path=_get(env, "STATE_PATH", d.state_path),
            acme_directory=acme_dir,
            acme_account_key_file=_get(env, "ACME_ACCOUNT_KEY_FILE", d.acme_account_key_file),
            acme_email=_get(env, "ACME_EMAIL", ""),
            acme_ca_bundle=_get(env, "ACME_CA_BUNDLE", ""),
            acme_timeout=_float(env, "ACME_TIMEOUT", d.acme_timeout, 1.0),
            dns_propagation_seconds=_float(env, "DNS_PROPAGATION_SECONDS", d.dns_propagation_seconds),
            certificate_deadline=_float(env, "CERTIFICATE_DEADLINE", d.certificate_deadline, 5.0),
            cloudflare_api=_get(env, "CLOUDFLARE_API", d.cloudflare_api).rstrip("/"),
            cloudflare_token=_get(env, "CLOUDFLARE_API_TOKEN", ""),
            cloudflare_zone_id=_get(env, "CLOUDFLARE_ZONE_ID", ""),
            cert_budget=_int(env, "CERT_BUDGET", d.cert_budget, 1),
            cert_hard_limit=_int(env, "CERT_HARD_LIMIT", d.cert_hard_limit, 1),
            certs_per_broker_week=_int(env, "CERTS_PER_BROKER_WEEK", d.certs_per_broker_week, 1),
            max_concurrent_issuance=_int(env, "MAX_CONCURRENT_ISSUANCE", d.max_concurrent_issuance, 1),
            registrations_per_ip_day=_int(env, "REGISTRATIONS_PER_IP_DAY", d.registrations_per_ip_day, 1),
            max_streams_per_broker=_int(env, "MAX_STREAMS_PER_BROKER", d.max_streams_per_broker, 1),
            max_streams_total=_int(env, "MAX_STREAMS_TOTAL", d.max_streams_total, 1),
            max_pending_handshakes=_int(env, "MAX_PENDING_HANDSHAKES", d.max_pending_handshakes, 1),
            max_handshakes_per_ip=_int(env, "MAX_HANDSHAKES_PER_IP", d.max_handshakes_per_ip, 1),
            max_streams_per_ip=_int(env, "MAX_STREAMS_PER_IP", d.max_streams_per_ip, 1),
            max_control_connections=_int(env, "MAX_CONTROL_CONNECTIONS", d.max_control_connections, 1),
            max_control_connections_per_ip=_int(env, "MAX_CONTROL_CONNECTIONS_PER_IP",
                                                d.max_control_connections_per_ip, 2),
            conn_rate_per_ip=_float(env, "CONN_RATE_PER_IP", d.conn_rate_per_ip, 0.1),
            conn_burst_per_ip=_int(env, "CONN_BURST_PER_IP", d.conn_burst_per_ip, 1),
            control_conn_rate_per_ip=_float(env, "CONTROL_CONN_RATE_PER_IP", d.control_conn_rate_per_ip, 0.1),
            control_conn_burst_per_ip=_int(env, "CONTROL_CONN_BURST_PER_IP", d.control_conn_burst_per_ip, 1),
            client_hello_timeout=_float(env, "CLIENT_HELLO_TIMEOUT", d.client_hello_timeout, 0.1),
            client_hello_max_bytes=_int(env, "CLIENT_HELLO_MAX_BYTES", d.client_hello_max_bytes, 512),
            stream_open_timeout=_float(env, "STREAM_OPEN_TIMEOUT", d.stream_open_timeout, 0.1),
            stream_first_byte_timeout=_float(env, "STREAM_FIRST_BYTE_TIMEOUT", d.stream_first_byte_timeout, 0.1),
            stream_idle_timeout=_float(env, "STREAM_IDLE_TIMEOUT", d.stream_idle_timeout, 1.0),
            control_ping_interval=_float(env, "CONTROL_PING_INTERVAL", d.control_ping_interval, 0.1),
            control_pong_timeout=_float(env, "CONTROL_PONG_TIMEOUT", d.control_pong_timeout, 0.1),
            ws_ping_interval=_float(env, "WS_PING_INTERVAL", d.ws_ping_interval, 0.1),
            log_level=_get(env, "LOG_LEVEL", d.log_level).upper(),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.domain or "." not in self.domain or not _is_hostname(self.domain):
            raise ConfigError("AKDBX_RELAY_DOMAIN must be a domain name")
        if not self.control_hostname:
            self.control_hostname = "relay." + self.domain
        if not _is_hostname(self.control_hostname) or "." not in self.control_hostname:
            raise ConfigError("AKDBX_RELAY_CONTROL_HOSTNAME must be a host name")
        if broker_id_from_host(self.control_hostname, self.domain) is not None:
            raise ConfigError("AKDBX_RELAY_CONTROL_HOSTNAME must not have the form of a broker name")
        if bool(self.control_cert_file) != bool(self.control_key_file):
            raise ConfigError("set both AKDBX_RELAY_CONTROL_CERT_FILE and AKDBX_RELAY_CONTROL_KEY_FILE, or neither")
        if self.health_host:
            try:
                loopback = ipaddress.ip_address(self.health_host).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise ConfigError("AKDBX_RELAY_HEALTH_HOST must be a loopback address (or empty)")
        if self.cert_hard_limit < self.cert_budget:
            raise ConfigError("AKDBX_RELAY_CERT_HARD_LIMIT must be at least AKDBX_RELAY_CERT_BUDGET")
        if self.client_hello_max_bytes > 65536:
            raise ConfigError("AKDBX_RELAY_CLIENT_HELLO_MAX_BYTES must be at most 65536")

    @property
    def state_dir(self) -> str:
        return os.path.dirname(os.path.abspath(self.state_path))

    @property
    def managed_control_tls(self) -> bool:
        """True when the relay obtains its own control certificate through ACME."""
        return not self.control_cert_file

    @property
    def control_tls_files(self) -> tuple[str, str]:
        """(certificate chain, private key) paths for the control host name."""
        if self.control_cert_file:
            return self.control_cert_file, self.control_key_file
        return (os.path.join(self.state_dir, "control-chain.pem"),
                os.path.join(self.state_dir, "control-key.pem"))

    @property
    def issuance_configured(self) -> bool:
        return bool(self.cloudflare_token and self.cloudflare_zone_id and self.acme_directory)
