import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from akdbx_relay.config import LE_STAGING, Config, ConfigError
from akdbx_relay.csr import CSRError, validate_csr
from akdbx_relay.names import (
    broker_id_from_host,
    hash_secret,
    is_valid_broker_id,
    new_broker_id,
    new_secret,
    new_stream_id,
)
from akdbx_relay.ratelimit import SlidingWindow, TokenBucket
from akdbx_relay.relay import rate_key
from akdbx_relay.store import DAY, WEEK, Budget, Store

from .helpers import csr_pem, make_csr, rsa_key

NAME = "abcdefghijkl.akdbx.link"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


# Names and secrets


def test_broker_ids():
    for _ in range(200):
        bid = new_broker_id()
        assert re.fullmatch(r"[a-z2-7]{12}", bid)
    assert len({new_broker_id() for _ in range(100)}) == 100


def test_reserved_and_short_labels_refused():
    for label in ("www", "api", "relay", "mail", "abc", "abcdefghijk", "abcdefghijklm", "abcdefghijk1",
                  "ABCDEFGHIJKL"):
        assert not is_valid_broker_id(label)
    assert is_valid_broker_id("abcdefghijkl")


def test_broker_id_from_host():
    assert broker_id_from_host(NAME, "akdbx.link") == "abcdefghijkl"
    assert broker_id_from_host("ABCDEFGHIJKL.AKDBX.LINK.", "akdbx.link") == "abcdefghijkl"
    assert broker_id_from_host("www.akdbx.link", "akdbx.link") is None
    assert broker_id_from_host("akdbx.link", "akdbx.link") is None
    assert broker_id_from_host("x.abcdefghijkl.akdbx.link", "akdbx.link") is None
    assert broker_id_from_host("abcdefghijkl.evilakdbx.link", "akdbx.link") is None
    assert broker_id_from_host("abcdefghijkl.akdbx.link.evil.com", "akdbx.link") is None


def test_secret_and_stream_ids():
    secret = new_secret()
    assert len(secret) == 43 and re.fullmatch(r"[A-Za-z0-9_-]{43}", secret)
    assert len(hash_secret(secret)) == 64 and secret not in hash_secret(secret)
    assert re.fullmatch(r"[0-9a-f]{32}", new_stream_id())


# Rate limits


def test_token_bucket():
    clock = Clock()
    tb = TokenBucket(rate=10, burst=3, clock=clock)
    assert [tb.allow("a") for _ in range(4)] == [True, True, True, False]
    assert tb.allow("b")
    clock.t += 0.1
    assert tb.allow("a") and not tb.allow("a")
    clock.t += 120
    tb.allow("c")
    assert len(tb) <= 2  # idle keys swept


def test_token_bucket_evicts_when_full():
    # R8: a full table used to refuse every new address.
    clock = Clock()
    tb = TokenBucket(rate=1, burst=2, clock=clock, max_keys=2)
    assert tb.allow("a") and tb.allow("b")
    assert tb.allow("a")  # "a" is now the most recently used
    assert tb.allow("c")  # evicts "b", the least recently used
    assert len(tb) == 2
    assert not tb.allow("a")  # "a" kept its (empty) bucket


def test_sliding_window_evicts_when_full():
    clock = Clock()
    sw = SlidingWindow(limit=1, window=DAY, clock=clock, max_keys=2)
    sw.record("a")
    sw.record("b")
    assert sw.check("c") == 0
    sw.record("c")
    assert len(sw) == 2
    assert sw.check("c") > 0


def test_sliding_window():
    clock = Clock()
    sw = SlidingWindow(limit=2, window=DAY, clock=clock)
    assert sw.check("ip") == 0
    sw.record("ip")
    sw.record("ip")
    wait = sw.check("ip")
    assert 0 < wait <= DAY
    assert sw.check("other") == 0
    clock.t += DAY
    assert sw.check("ip") == 0
    assert len(sw) == 0


def test_rate_key():
    assert rate_key("192.0.2.1") == "192.0.2.1"
    assert rate_key("::ffff:192.0.2.1") == "192.0.2.1"
    assert rate_key("2001:db8:1:2:3:4:5:6") == rate_key("2001:db8:1:2:ffff::1") == "2001:db8:1:2::/64"
    assert rate_key("2001:db8:1:3::1") != rate_key("2001:db8:1:2::1")


# CSR checks


def test_valid_ecdsa_csr():
    assert validate_csr(csr_pem(make_csr(NAME)), NAME).startswith(b"-----BEGIN CERTIFICATE REQUEST-----")


def test_valid_rsa_csr_and_cn():
    validate_csr(csr_pem(make_csr(NAME, rsa_key(2048), cn=NAME)), NAME)


@pytest.mark.parametrize(
    "build",
    [
        lambda: make_csr(NAME, rsa_key(1024)),
        lambda: make_csr(NAME, ec.generate_private_key(ec.SECP384R1())),
        lambda: make_csr(NAME, ed25519.Ed25519PrivateKey.generate(), hash_alg=False),
        lambda: make_csr("other12chars.akdbx.link"),
        lambda: make_csr(None, sans=[x509.DNSName(NAME), x509.DNSName("zzzzzzzzzzzz.akdbx.link")]),
        lambda: make_csr(None, sans=[x509.DNSName(NAME), x509.IPAddress(__import__("ipaddress").ip_address("192.0.2.1"))]),
        lambda: make_csr(None, sans=[x509.IPAddress(__import__("ipaddress").ip_address("192.0.2.1"))]),
        lambda: make_csr(None, sans=[]),
        lambda: make_csr(NAME, cn="evil.example.com"),
        lambda: make_csr(NAME, extra_ext=x509.BasicConstraints(ca=True, path_length=None)),
        lambda: make_csr(NAME, sans=[x509.DNSName("*.akdbx.link")]),
    ],
)
def test_bad_csrs(build):
    with pytest.raises(CSRError):
        validate_csr(csr_pem(build()), NAME)


@pytest.mark.parametrize("pem", ["", "garbage", None, 5, "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
                                 "é" * 10, "x" * 20000])
def test_unparseable_csrs(pem):
    with pytest.raises(CSRError):
        validate_csr(pem, NAME)


def test_two_csr_blocks_refused():
    pem = csr_pem(make_csr(NAME))
    with pytest.raises(CSRError):
        validate_csr(pem + pem, NAME)


def test_csr_with_bad_signature():
    pem = csr_pem(make_csr(NAME))
    der = x509.load_pem_x509_csr(pem.encode()).public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER)
    tampered = bytearray(der)
    tampered[-5] ^= 0x01
    import base64
    body = base64.encodebytes(bytes(tampered)).decode()
    with pytest.raises(CSRError):
        validate_csr("-----BEGIN CERTIFICATE REQUEST-----\n" + body + "-----END CERTIFICATE REQUEST-----\n", NAME)


# Store and budget


def test_store_and_budget(tmp_path):
    clock = Clock(1_000_000.0)
    store = Store(str(tmp_path / "s.sqlite3"), clock=clock)
    budget = Budget(store, budget=3, hard_limit=4, per_broker_week=2)
    assert budget.registration_retry_after() is None
    for i in range(3):
        assert store.add_broker(f"broker{i:06d}ab", f"hash{i}", "t")
    assert not store.add_broker("broker000000ab", "other", "t")
    assert not store.add_broker("brokerzzzzzzab", "hash0", "t")
    # Three pending registrations hold the budget.
    wait = budget.registration_retry_after()
    assert wait is not None and 0 < wait <= DAY + 1
    # Pending reservations expire after a day.
    clock.t += DAY + 1
    assert budget.registration_retry_after() is None
    for i in range(3):
        assert store.record_certificate(f"broker{i:06d}ab", clock.t + 90 * DAY) is True
    assert store.record_certificate("broker000000ab", clock.t + 90 * DAY) is False  # renewal
    wait = budget.registration_retry_after()
    assert wait is not None and WEEK - 10 <= wait <= WEEK + 1
    assert budget.first_issuance_retry_after() is None  # 3 < hard limit 4
    assert budget.broker_retry_after("broker000000ab") is not None  # 2 this week
    assert budget.broker_retry_after("broker000001ab") is None
    clock.t += WEEK
    assert budget.registration_retry_after() is None
    assert budget.broker_retry_after("broker000000ab") is None
    store.close()


def test_txt_markers_and_migration(tmp_path):
    import sqlite3
    path = str(tmp_path / "s.sqlite3")
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE acme_txt (record_id TEXT PRIMARY KEY, created_at REAL NOT NULL)")
    db.execute("INSERT INTO acme_txt VALUES ('old-record', 1.0)")
    db.commit()
    db.close()
    store = Store(path)
    markers = store.txt_markers()
    assert [(m.record_id, m.name) for m in markers] == [("old-record", "")]
    m = store.add_txt_marker("_acme-challenge.x.akdbx.link", "value")
    assert m.record_id is None
    store.set_txt_marker_record(m.id, "rid")
    assert store.txt_markers()[-1].record_id == "rid"
    store.remove_txt_marker(m.id)
    store.remove_txt_marker(markers[0].id)
    assert store.txt_markers() == []
    store.close()


def test_store_file_mode_and_no_plain_secret(tmp_path):
    import os
    path = tmp_path / "state" / "s.sqlite3"
    store = Store(str(path))
    store.add_broker("abcdefghijkl", hash_secret("the-secret-value-xyz"), "akdbx/1")
    store.close()
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert b"the-secret-value-xyz" not in path.read_bytes()


# Config


def test_config_from_env():
    cfg = Config.from_env({
        "AKDBX_RELAY_ACME_DIRECTORY": "staging",
        "AKDBX_RELAY_PUBLIC_HOSTS": "0.0.0.0, ::",
        "AKDBX_RELAY_CERT_BUDGET": "30",
        "AKDBX_RELAY_CLOUDFLARE_API_TOKEN": "tok",
        "AKDBX_RELAY_CLOUDFLARE_ZONE_ID": "zone",
    })
    assert cfg.acme_directory == LE_STAGING
    assert cfg.public_hosts == ["0.0.0.0", "::"]
    assert cfg.cert_budget == 30
    assert cfg.issuance_configured
    assert "tok" not in repr(cfg)


def test_config_control_host_defaults():
    cfg = Config.from_env({})
    assert cfg.control_hostname == "relay.akdbx.link"
    assert cfg.health_host == "127.0.0.1" and cfg.managed_control_tls
    assert cfg.control_tls_files == ("/var/lib/akdbx-relay/control-chain.pem",
                                     "/var/lib/akdbx-relay/control-key.pem")
    assert cfg.certificate_deadline == 90
    other = Config.from_env({"AKDBX_RELAY_DOMAIN": "example.org", "AKDBX_RELAY_HEALTH_HOST": ""})
    assert other.control_hostname == "relay.example.org" and other.health_host == ""


@pytest.mark.parametrize("env", [
    {"AKDBX_RELAY_PUBLIC_PORT": "x"},
    # R5: no proxy header is trusted, and the old proxy settings are refused.
    {"AKDBX_RELAY_TRUSTED_PROXY_IPS": "127.0.0.1"},
    {"AKDBX_RELAY_CONTROL_HOST": "127.0.0.1"},
    {"AKDBX_RELAY_CONTROL_PORT": "8771"},
    {"AKDBX_RELAY_HEALTH_HOST": "0.0.0.0"},
    {"AKDBX_RELAY_HEALTH_HOST": "localhost"},
    {"AKDBX_RELAY_CONTROL_HOSTNAME": "abcdefghijkl.akdbx.link"},  # a broker-shaped name
    {"AKDBX_RELAY_CONTROL_HOSTNAME": "bad_name.akdbx.link"},
    {"AKDBX_RELAY_CONTROL_CERT_FILE": "/x.pem"},  # key file missing
    {"AKDBX_RELAY_CERTIFICATE_DEADLINE": "1"},
    {"AKDBX_RELAY_CERT_BUDGET": "50", "AKDBX_RELAY_CERT_HARD_LIMIT": "45"},
    {"AKDBX_RELAY_DOMAIN": "localhost"},
    {"AKDBX_RELAY_CONN_RATE_PER_IP": "0"},
])
def test_config_errors(env):
    with pytest.raises(ConfigError):
        Config.from_env(env)
