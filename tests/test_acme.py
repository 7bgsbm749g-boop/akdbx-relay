import logging

import pytest
from cryptography import x509

from akdbx_relay.cloudflare import CloudflareDNS
from akdbx_relay.issuer import ACMEIssuer, IssuanceError, IssuanceRateLimited
from akdbx_relay.store import Store

from .fakes import FakeACME, FakeCloudflare
from .helpers import csr_pem, http, make_config, make_csr

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
    assert store.txt_records() == []
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
    assert cf.records == {} and len(cf.deleted) == 1 and store.txt_records() == []
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
    assert len(cf.records) == 1 and len(store.txt_records()) == 1
    cf.fail_delete = False
    await issuer.cleanup_stale_records()
    assert cf.records == {} and store.txt_records() == []
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
    status, _, reg = await http(relay.control_port, "POST", "/api/v1/register", {"protocol": 1})
    assert status == 201
    csr = csr_pem(make_csr(reg["name"]))
    status, _, body = await http(relay.control_port, "POST", "/api/v1/certificate", {"csr": csr},
                                 {"Authorization": f"Bearer {reg['secret']}"})
    assert status == 200, body
    leaf = x509.load_pem_x509_certificate(body["certificate"].encode())
    assert leaf.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ") == body["not_after"]
    assert relay.store.first_time_certificates() and cf.records == {}
    # No secret, CSR or certificate text in the logs.
    for needle in (reg["secret"], csr.splitlines()[1], body["certificate"].splitlines()[1], cf.token):
        assert needle not in caplog.text
    store.close()
