import logging

import pytest
from cryptography import x509

from akdbx_relay.cloudflare import CloudflareDNS
from akdbx_relay.issuer import ACMEIssuer, IssuanceError, IssuanceRateLimited
from akdbx_relay.store import Store

from .fakes import FakeACME, FakeCloudflare
from .helpers import api, csr_pem, make_config, make_csr

NAME = "abcdefghijkl.akdbx.link"


@pytest.fixture
def fakes():
    cf = FakeCloudflare().start()
    acme = FakeACME(cf).start()
    yield acme, cf
    acme.stop()
    cf.stop()


def make_issuer(tmp_path, acme, cf, token=None):
    cfg = make_config(tmp_path, acme_directory=acme.base + "/directory", cloudflare_api=cf.api,
                      cloudflare_token=token or cf.token, cloudflare_zone_id=cf.zone_id)
    store = Store(cfg.state_path)
    dns = CloudflareDNS(cfg.cloudflare_api, cfg.cloudflare_token, cfg.cloudflare_zone_id, timeout=5)
    return cfg, store, ACMEIssuer(cfg, store, dns)


async def test_issue_through_fake_acme(tmp_path, fakes):
    acme, cf = fakes
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    chain = await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    leaf = x509.load_pem_x509_certificate(chain.encode())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [NAME]
    assert chain.count("BEGIN CERTIFICATE") == 2
    # The TXT record was created at the right name, then removed.
    assert [r["name"] for r in cf.created] == ["_acme-challenge." + NAME]
    assert cf.records == {} and len(cf.deleted) == 1
    assert store.txt_markers() == []
    # The account is registered once and reused.
    await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    assert acme.new_account_calls == 1
    assert (tmp_path / "acme-account.pem").stat().st_mode & 0o777 == 0o600
    store.close()


async def test_existing_account_key_reuses_account(tmp_path, fakes):
    acme, cf = fakes
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    store.set_meta(issuer._meta_key, "")  # forget the URL, keep the key
    await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    assert len(acme.accounts) == 1
    store.close()


async def test_validation_failure_removes_txt(tmp_path, fakes):
    acme, cf = fakes
    acme.fail_validation = True
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    with pytest.raises(IssuanceError):
        await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    assert cf.records == {} and len(cf.deleted) == 1 and store.txt_markers() == []
    store.close()


async def test_rate_limited(tmp_path, fakes):
    acme, cf = fakes
    acme.rate_limited = True
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    with pytest.raises(IssuanceRateLimited):
        await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    store.close()


async def test_cloudflare_auth_failure_is_reported_without_token(tmp_path, fakes, caplog):
    acme, cf = fakes
    _, store, issuer = make_issuer(tmp_path, acme, cf, token="wrong-token-value-123")
    with pytest.raises(IssuanceError) as exc:
        await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    assert "wrong-token-value-123" not in str(exc.value)
    assert "wrong-token-value-123" not in caplog.text
    store.close()


async def test_stale_txt_records_cleaned_at_start(tmp_path, fakes):
    acme, cf = fakes
    cf.fail_delete = True
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode())
    assert len(cf.records) == 1 and len(store.txt_markers()) == 1
    cf.fail_delete = False
    await issuer.cleanup_stale_records()
    assert cf.records == {} and store.txt_markers() == []
    store.close()


async def test_certificate_api_with_fake_acme(tmp_path, fakes, relay_factory, caplog):
    caplog.set_level(logging.DEBUG)
    acme, cf = fakes
    cfg, store, issuer = make_issuer(tmp_path / "issuer", acme, cf)
    relay = await relay_factory(issuer)
    # The relay and the issuer must share one store for the TXT bookkeeping.
    issuer.store = relay.store
    issuer.cfg = relay.cfg
    relay.cfg.acme_directory = cfg.acme_directory
    relay.cfg.acme_account_key_file = cfg.acme_account_key_file
    status, _, reg = await api(relay, "POST", "/api/v1/register", {"protocol": 1})
    assert status == 201
    csr = csr_pem(make_csr(reg["name"]))
    status, _, body = await api(relay, "POST", "/api/v1/certificate", {"csr": csr},
                                 {"Authorization": f"Bearer {reg['secret']}"})
    assert status == 200, body
    leaf = x509.load_pem_x509_certificate(body["certificate"].encode())
    assert leaf.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ") == body["not_after"]
    assert relay.store.first_time_certificates() and cf.records == {}
    # No secret, CSR or certificate text in the logs.
    for needle in (reg["secret"], csr.splitlines()[1], body["certificate"].splitlines()[1], cf.token):
        assert needle not in caplog.text
    store.close()


# R7: cleanup markers and start-up reconciliation


async def test_cancelled_txt_create_is_removed_at_next_start(tmp_path, fakes):
    import asyncio

    acme, cf = fakes
    cf.create_delay = 0.8  # the record exists, but the answer is late
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    task = asyncio.create_task(issuer.issue(NAME, csr_pem(make_csr(NAME)).encode()))
    for _ in range(300):
        if cf.created:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(1.0)  # the create call finishes in its thread
    assert len(cf.records) == 1
    assert [m.record_id for m in store.txt_markers()] == [None]  # written before the create
    # Next start: the record is found by name and value, and removed.
    cf.create_delay = 0
    await issuer.cleanup_stale_records()
    assert cf.records == {} and store.txt_markers() == []
    store.close()


async def test_start_up_removes_old_relay_owned_records_only(tmp_path, fakes):
    from akdbx_relay.issuer import RECORD_COMMENT

    acme, cf = fakes
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    stale = cf.add_record("_acme-challenge.zzzzzzzzzzzz.akdbx.link", "v1", RECORD_COMMENT, age_seconds=3600)
    young = cf.add_record("_acme-challenge.yyyyyyyyyyyy.akdbx.link", "v2", RECORD_COMMENT)
    foreign = cf.add_record("_acme-challenge.xxxxxxxxxxxx.akdbx.link", "v3", "someone else", age_seconds=3600)
    other_zone = cf.add_record("_acme-challenge.example.com", "v4", RECORD_COMMENT, age_seconds=3600)
    await issuer.cleanup_stale_records()
    assert stale not in cf.records
    assert {young, foreign, other_zone} <= set(cf.records)
    store.close()


# R9: the issuer honours the request deadline


async def test_issue_refuses_when_the_deadline_is_too_close(tmp_path, fakes):
    import asyncio

    acme, cf = fakes
    _, store, issuer = make_issuer(tmp_path, acme, cf)
    loop = asyncio.get_running_loop()
    with pytest.raises(IssuanceError):
        await issuer.issue(NAME, csr_pem(make_csr(NAME)).encode(), deadline=loop.time() + 1)
    assert cf.created == []
    store.close()


# R1: the relay's own control certificate through the same ACME code


async def test_relay_obtains_its_control_certificate_through_acme(tmp_path, fakes, relay_factory):
    import asyncio
    import os

    from .helpers import http

    acme, cf = fakes
    cfg, store, issuer = make_issuer(tmp_path / "issuer", acme, cf)
    relay = await relay_factory(issuer, managed_tls=True)
    issuer.store = relay.store
    issuer.cfg = relay.cfg
    relay.cfg.acme_directory = cfg.acme_directory
    relay.cfg.acme_account_key_file = cfg.acme_account_key_file
    for _ in range(500):
        if relay.control_tls.context is not None:
            break
        await asyncio.sleep(0.01)
    assert relay.control_tls.context is not None
    assert [r["name"] for r in cf.created] == ["_acme-challenge.relay.akdbx.link"]
    assert cf.records == {}
    chain_path, key_path = relay.cfg.control_tls_files
    assert os.stat(key_path).st_mode & 0o777 == 0o600
    assert os.stat(chain_path).st_mode & 0o777 == 0o600
    status, _, body = await http(relay.public_port, "GET", "/api/v1/health",
                                 ssl_ctx=acme.ca.client_context(), server_hostname="relay.akdbx.link")
    assert status == 200 and body["status"] == "ok"
    store.close()
