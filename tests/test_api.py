import sqlite3

import pytest

from akdbx_relay.issuer import IssuanceError, IssuanceRateLimited

from .helpers import FakeIssuer, api, control_client_context, csr_pem, make_csr


async def register(relay, headers=None, body=None):
    return await api(relay, "POST", "/api/v1/register",
                      body if body is not None else {"protocol": 1, "client": "akdbx/test"}, headers)


async def test_health(relay_factory):
    relay = await relay_factory()
    status, headers, body = await api(relay, "GET", "/api/v1/health")
    assert status == 200
    assert body["status"] == "ok" and body["protocol"] == 1 and body["registrations"] == "open"
    assert headers["cache-control"] == "no-store"


async def test_register_shape_and_secret_hash_only(relay_factory):
    relay = await relay_factory()
    status, _, body = await register(relay)
    assert status == 201
    bid = body["broker_id"]
    assert body["name"] == f"{bid}.akdbx.link"
    assert body["protocol"] == 1 and body["public_port"] == relay.cfg.advertised_port
    assert len(body["secret"]) == 43
    raw = open(relay.cfg.state_path, "rb").read()
    db = sqlite3.connect(relay.cfg.state_path)
    dump = "\n".join(db.iterdump())
    db.close()
    assert body["secret"] not in dump and body["secret"].encode() not in raw


@pytest.mark.parametrize("payload,code", [
    ({"protocol": 2}, "unsupported_protocol"),
    ({}, "unsupported_protocol"),
    ({"protocol": 1, "client": 5}, "bad_request"),
    ({"protocol": 1, "client": "x" * 65}, "bad_request"),
    ([1, 2], "bad_request"),
])
async def test_register_bad_requests(relay_factory, payload, code):
    relay = await relay_factory()
    status, _, body = await register(relay, body=payload)
    assert status == 400 and body["error"] == code


async def test_register_not_json(relay_factory):
    relay = await relay_factory()
    status, _, body = await api(relay, "POST", "/api/v1/register", raw_body=b"{nope")
    assert status == 400 and body["error"] == "bad_request"


async def test_chunked_body(relay_factory):
    relay = await relay_factory()
    data = b'{"protocol": 1}'
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)
    status, _, body = await api(relay, "POST", "/api/v1/register", raw_body=chunked,
                                 headers={"Transfer-Encoding": "chunked"})
    assert status == 201, body


async def test_body_too_large(relay_factory):
    relay = await relay_factory()
    status, _, body = await api(relay, "POST", "/api/v1/register", raw_body=b"x" * 5000)
    assert status == 413


async def test_unknown_route_and_method(relay_factory):
    relay = await relay_factory()
    assert (await api(relay, "GET", "/nope"))[0] == 404
    assert (await api(relay, "GET", "/api/v1/register"))[0] == 405
    assert (await api(relay, "POST", "/api/v1/connect", {}))[0] == 405


async def test_registration_rate_limit_per_ip(relay_factory):
    relay = await relay_factory(registrations_per_ip_day=2)
    for _ in range(2):
        assert (await register(relay))[0] == 201
    status, headers, body = await register(relay)
    assert status == 429 and body["error"] == "rate_limited"
    assert int(headers["retry-after"]) > 0 and body["retry_after"] > 0


async def test_cf_connecting_ip_is_ignored(relay_factory):
    # R5: no proxy is in the control path, so no forwarded-address header is
    # trusted; the limit uses the TCP peer (127.0.0.1 here).
    relay = await relay_factory(registrations_per_ip_day=1)
    assert (await register(relay, {"CF-Connecting-IP": "198.51.100.1"}))[0] == 201
    assert (await register(relay, {"CF-Connecting-IP": "198.51.100.2"}))[0] == 429
    assert (await register(relay, {"X-Forwarded-For": "198.51.100.3"}))[0] == 429


async def test_duplicate_sensitive_headers_refused(relay_factory):
    relay = await relay_factory()
    status = (await api(relay, "POST", "/api/v1/register", {"protocol": 1},
                        headers={"Authorization": "Bearer a", "authorization": "Bearer b"}))[0]
    assert status == 400


async def test_budget_pauses_new_registrations_but_not_renewals(relay_factory):
    issuer = FakeIssuer()
    relay = await relay_factory(issuer, cert_budget=2, cert_hard_limit=3)
    regs = []
    for _ in range(2):
        status, _, body = await register(relay)
        assert status == 201
        regs.append(body)
    # Two registrations without certificates already hold the budget.
    status, headers, body = await register(relay)
    assert status == 503 and body["error"] == "registrations_paused"
    assert body["retry_after"] >= 60 and headers["retry-after"] == str(body["retry_after"])
    health = (await api(relay, "GET", "/api/v1/health"))[2]
    assert health["registrations"] == "paused"
    # Both registered brokers can still get their first certificate, and renew.
    for reg in regs:
        csr = csr_pem(make_csr(reg["name"]))
        status, _, body = await api(relay, "POST", "/api/v1/certificate", {"csr": csr},
                                     {"Authorization": f"Bearer {reg['secret']}"})
        assert status == 200, body
        assert body["certificate"].startswith("-----BEGIN CERTIFICATE-----")
        assert body["not_after"].endswith("Z")
    reg = regs[0]
    status, _, _ = await api(relay, "POST", "/api/v1/certificate",
                              {"csr": csr_pem(make_csr(reg["name"]))},
                              {"Authorization": f"Bearer {reg['secret']}"})
    assert status == 200
    assert (await register(relay))[0] == 503


async def test_first_issuance_paused_at_hard_limit(relay_factory):
    issuer = FakeIssuer()
    relay = await relay_factory(issuer, cert_budget=1, cert_hard_limit=1)
    _, _, a = await register(relay)
    # Simulate a first-time certificate issued to another broker this week.
    relay.store.add_broker("zzzzzzzzzzzz", "h", "t")
    relay.store.record_certificate("zzzzzzzzzzzz", 0)
    status, _, body = await api(relay, "POST", "/api/v1/certificate",
                                 {"csr": csr_pem(make_csr(a["name"]))},
                                 {"Authorization": f"Bearer {a['secret']}"})
    assert status == 503 and body["error"] == "issuance_paused" and body["retry_after"] > 0
    assert issuer.calls == []


async def test_per_broker_certificate_limit(relay_factory):
    issuer = FakeIssuer()
    relay = await relay_factory(issuer, certs_per_broker_week=2)
    _, _, a = await register(relay)
    auth = {"Authorization": f"Bearer {a['secret']}"}
    for _ in range(2):
        status, _, _ = await api(relay, "POST", "/api/v1/certificate",
                                  {"csr": csr_pem(make_csr(a["name"]))}, auth)
        assert status == 200
    status, _, body = await api(relay, "POST", "/api/v1/certificate",
                                 {"csr": csr_pem(make_csr(a["name"]))}, auth)
    assert status == 429 and body["error"] == "rate_limited"
    assert len(issuer.calls) == 2


@pytest.mark.parametrize("auth", [None, "Bearer", "Bearer wrongwrongwrongwrongwrongwrongwrongwrongwro",
                                  "Basic abc", "Bearer a b c", "Bearer " + "é" * 43])
async def test_certificate_auth_failures(relay_factory, auth):
    relay = await relay_factory(FakeIssuer())
    await register(relay)
    headers = {"Authorization": auth} if auth else {}
    status, _, body = await api(relay, "POST", "/api/v1/certificate", {"csr": "x"}, headers)
    assert status == 401 and body["error"] == "unauthorized"


async def test_certificate_bad_csr(relay_factory):
    issuer = FakeIssuer()
    relay = await relay_factory(issuer)
    _, _, a = await register(relay)
    _, _, b = await register(relay)
    auth = {"Authorization": f"Bearer {a['secret']}"}
    for csr in ["junk", csr_pem(make_csr(b["name"])), None]:
        status, _, body = await api(relay, "POST", "/api/v1/certificate", {"csr": csr}, auth)
        assert status == 400 and body["error"] == "bad_csr"
    assert issuer.calls == []


async def test_certificate_issuer_errors(relay_factory):
    issuer = FakeIssuer()
    relay = await relay_factory(issuer)
    _, _, a = await register(relay)
    auth = {"Authorization": f"Bearer {a['secret']}"}
    issuer.fail = IssuanceError("boom")
    status, _, body = await api(relay, "POST", "/api/v1/certificate",
                                 {"csr": csr_pem(make_csr(a["name"]))}, auth)
    assert status == 502 and body["error"] == "acme_failed"
    issuer.fail = IssuanceRateLimited(1800)
    status, _, body = await api(relay, "POST", "/api/v1/certificate",
                                 {"csr": csr_pem(make_csr(a["name"]))}, auth)
    assert status == 503 and body["error"] == "issuance_paused" and body["retry_after"] == 1800
    # Failed orders are not counted.
    assert relay.store.broker_certificates_this_week(a["broker_id"]) == []


async def test_certificate_without_issuer(relay_factory):
    relay = await relay_factory(None)
    _, _, a = await register(relay)
    status, _, body = await api(relay, "POST", "/api/v1/certificate",
                                 {"csr": csr_pem(make_csr(a["name"]))},
                                 {"Authorization": f"Bearer {a['secret']}"})
    assert status == 503 and body["error"] == "issuance_paused"


async def test_websocket_endpoints_need_auth_and_upgrade(relay_factory):
    relay = await relay_factory()
    _, _, a = await register(relay)
    status, _, body = await api(relay, "GET", "/api/v1/connect")
    assert status == 401
    status, _, body = await api(relay, "GET", "/api/v1/connect",
                                 headers={"Authorization": f"Bearer {a['secret']}"})
    assert status == 400 and body["error"] == "websocket_required"
    status, _, body = await api(relay, "GET", "/api/v1/stream/" + "0" * 32,
                                 headers={"Authorization": f"Bearer {a['secret']}"})
    assert status == 404 and body["error"] == "unknown_stream"
    status, _, body = await api(relay, "GET", "/api/v1/stream/../../x",
                                 headers={"Authorization": f"Bearer {a['secret']}"})
    assert status == 404


async def test_slow_or_bad_http_heads(relay_factory):
    import asyncio
    relay = await relay_factory()

    async def tls():
        return await asyncio.open_connection("127.0.0.1", relay.public_port, ssl=control_client_context(),
                                             server_hostname=relay.cfg.control_hostname)

    reader, writer = await tls()
    writer.write(b"GET /api/v1/health HTTP/1.1\r\n" + b"X: " + b"a" * 20000 + b"\r\n\r\n")
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 5)
    assert b" 431 " in data.split(b"\r\n")[0]
    writer.close()
    reader, writer = await tls()
    writer.write(b"NONSENSE\r\n\r\n")
    data = await asyncio.wait_for(reader.read(), 5)
    assert b" 400 " in data.split(b"\r\n")[0]
    writer.close()


async def test_hard_limit_counts_orders_in_progress(relay_factory):
    import asyncio

    class SlowIssuer(FakeIssuer):
        async def issue(self, name, csr_pem_bytes, deadline=None):
            await asyncio.sleep(0.3)
            return await super().issue(name, csr_pem_bytes, deadline)

    relay = await relay_factory(SlowIssuer(), cert_budget=1, cert_hard_limit=1)
    _, _, a = await register(relay)
    relay.cfg.cert_budget = 5  # let the second registration through
    relay.budget.budget = 5
    _, _, b = await register(relay)

    async def cert(reg):
        return await api(relay, "POST", "/api/v1/certificate",
                          {"csr": csr_pem(make_csr(reg["name"]))}, {"Authorization": f"Bearer {reg['secret']}"})

    results = await asyncio.gather(cert(a), cert(b))
    assert sorted(r[0] for r in results) == [200, 503]


async def test_broker_info_needs_auth_and_reports_port(relay_factory):
    relay = await relay_factory()
    status, _, body = await register(relay)
    assert status == 201
    secret = body["secret"]
    status, _, info = await api(relay, "GET", "/api/v1/broker", headers={"Authorization": f"Bearer {secret}"})
    assert status == 200
    assert info == {"protocol": 1, "name": body["name"], "public_port": relay.cfg.advertised_port,
                    "relay_url": f"https://{relay.cfg.control_hostname}:{relay.cfg.advertised_port}"}
    assert secret not in str(info)
    for auth in (None, "Bearer " + "x" * 43):
        status, _, err = await api(relay, "GET", "/api/v1/broker",
                                   headers={"Authorization": auth} if auth else None)
        assert status == 401 and err["error"] == "unauthorized"
    status, _, err = await api(relay, "POST", "/api/v1/broker", {}, headers={"Authorization": f"Bearer {secret}"})
    assert status == 405


async def test_broker_info_url_has_no_port_for_443(relay_factory):
    relay = await relay_factory(advertised_port=443)
    _, _, body = await register(relay)
    status, _, info = await api(relay, "GET", "/api/v1/broker",
                                headers={"Authorization": f"Bearer {body['secret']}"})
    assert status == 200 and info["public_port"] == 443
    assert info["relay_url"] == f"https://{relay.cfg.control_hostname}"


async def test_extra_public_listener_serves_the_same_api(relay_factory):
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        extra = s.getsockname()[1]
    relay = await relay_factory(public_extra_listen=[("127.0.0.1", extra)])
    from .helpers import http
    status, _, body = await http(extra, "GET", "/api/v1/health", ssl_ctx=control_client_context(),
                                 server_hostname=relay.cfg.control_hostname)
    assert status == 200 and body["status"] == "ok"
