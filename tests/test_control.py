"""The control API on the relay's own TLS (R1), per-address limits (R8),
deadlines (R3, R9) and TCP-peer rate keys (R5)."""

import asyncio
import contextlib
import datetime
import json
import os
import ssl

import pytest

from akdbx_relay import controltls
from akdbx_relay.controltls import ControlTLSError
from akdbx_relay.relay import ControlChannel

from .helpers import (
    CA,
    FakeIssuer,
    api,
    client_hello,
    control_client_context,
    csr_pem,
    http,
    make_csr,
    start_relay,
    write_control_cert,
)
from .test_e2e import closed_without_data, control, stream_ws, wait_for


async def register(relay):
    status, _, body = await api(relay, "POST", "/api/v1/register", {"protocol": 1})
    assert status == 201, body
    return body


# R1: the control API is served only inside the relay's own TLS


async def test_control_api_is_served_on_the_public_port_with_the_relays_certificate(relay_factory):
    relay = await relay_factory()
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", relay.public_port, ssl=control_client_context(), server_hostname="relay.akdbx.link")
    cert = writer.get_extra_info("peercert")
    assert ("DNS", "relay.akdbx.link") in cert["subjectAltName"]
    writer.write(b"GET /api/v1/health HTTP/1.1\r\nHost: relay.akdbx.link\r\n\r\n")
    data = await asyncio.wait_for(reader.read(), 5)
    assert data.startswith(b"HTTP/1.1 200 ") and b'"status":"ok"' in data
    writer.close()


async def test_plain_port_answers_only_health(relay_factory):
    relay = await relay_factory()
    reg = await register(relay)
    auth = {"Authorization": f"Bearer {reg['secret']}"}
    port = relay.health_port
    assert (await http(port, "GET", "/api/v1/health"))[0] == 200
    # No secret-bearing route on the plain port (the one a local proxy could reach).
    assert (await http(port, "POST", "/api/v1/register", {"protocol": 1}))[0] == 404
    assert (await http(port, "POST", "/api/v1/certificate", {"csr": "x"}, auth))[0] == 404
    assert (await http(port, "GET", "/api/v1/connect", headers=auth))[0] == 404
    assert (await http(port, "GET", "/api/v1/stream/" + "0" * 32, headers=auth))[0] == 404


async def test_health_port_can_be_disabled(relay_factory):
    relay = await relay_factory(health_host="")
    assert relay._health_server is None
    assert (await api(relay, "GET", "/api/v1/health"))[0] == 200


async def test_other_names_are_not_terminated(relay_factory):
    relay = await relay_factory()
    # Only the control host name reaches the relay's TLS; a broker name or a
    # look-alike is passed through (and closed here, since no broker is online).
    for name in ("abcdefghijkl.akdbx.link", "relay.akdbx.link.evil.com", "akdbx.link"):
        assert await closed_without_data(relay.public_port, client_hello(name))


async def test_control_name_without_a_certificate_is_closed(relay_factory):
    relay = await relay_factory(None, managed_tls=True)  # no issuer, no files
    assert relay.control_tls.context is None
    assert await closed_without_data(relay.public_port, client_hello("relay.akdbx.link"))


async def test_operator_certificate_must_name_the_control_host(tmp_path):
    cert_file, key_file = write_control_cert(tmp_path / "wrong", "other.akdbx.link")
    with pytest.raises(ControlTLSError):
        await start_relay(tmp_path, None, control_cert_file=cert_file, control_key_file=key_file)


async def test_managed_control_certificate_is_kept_and_renewed(tmp_path, monkeypatch):
    monkeypatch.setattr(controltls, "RETRY_MIN", 0.05)
    monkeypatch.setattr(controltls, "CHECK_MAX", 0.05)
    issuer = FakeIssuer()
    relay = await start_relay(tmp_path, issuer, managed_tls=True)
    try:
        await wait_for(lambda: relay.control_tls.context is not None)
        assert issuer.calls == ["relay.akdbx.link"]
        chain_path, key_path = relay.cfg.control_tls_files
        assert os.path.dirname(chain_path) == str(tmp_path)
        assert os.stat(key_path).st_mode & 0o777 == 0o600
        status, _, _ = await http(relay.public_port, "GET", "/api/v1/health",
                                  ssl_ctx=issuer.ca.client_context(), server_hostname="relay.akdbx.link")
        assert status == 200
        key_before = open(key_path, "rb").read()
        # Two thirds of the lifetime later, the relay renews with the same key.
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=61)
        relay.control_tls._now = lambda: later
        await wait_for(lambda: len(issuer.calls) == 2)
        assert open(key_path, "rb").read() == key_before
    finally:
        await relay.stop()
        relay.store.close()
    # A restart reuses the stored certificate.
    relay = await start_relay(tmp_path, issuer, managed_tls=True)
    try:
        assert relay.control_tls.context is not None
        await asyncio.sleep(0.2)
        assert len(issuer.calls) == 2
    finally:
        await relay.stop()
        relay.store.close()


# R5: rate limits use the TCP peer address


async def test_registration_limit_uses_the_tcp_peer(relay_factory):
    relay = await relay_factory(registrations_per_ip_day=1)
    assert (await api(relay, "POST", "/api/v1/register", {"protocol": 1},
                      {"CF-Connecting-IP": "198.51.100.7"}))[0] == 201
    status, _, body = await api(relay, "POST", "/api/v1/register", {"protocol": 1},
                                {"CF-Connecting-IP": "198.51.100.8"})
    assert status == 429 and body["error"] == "rate_limited"


# R3: the control-channel open send is inside the stream-open deadline


async def test_open_stream_deadline_covers_the_open_send(relay_factory):
    relay = await relay_factory(stream_open_timeout=0.3)

    class StuckWS:
        open = True

        async def send(self, data):
            await asyncio.Event().wait()  # the broker stopped reading

    chan = ControlChannel("abcdefghijkl", StuckWS(), 0.0)
    assert await asyncio.wait_for(relay._open_stream(chan), 2) is None
    assert relay.pending == {}


# R8: per-address handshake and stream limits, first-byte timeout


async def test_open_handshakes_are_limited_per_address(relay_factory):
    relay = await relay_factory(max_handshakes_per_ip=2, client_hello_timeout=5, conn_burst_per_ip=100)
    held = [await asyncio.open_connection("127.0.0.1", relay.public_port) for _ in range(2)]
    await wait_for(lambda: relay.pending_handshakes == 2)
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
    assert await asyncio.wait_for(reader.read(), 1) == b""  # refused at once, not after 5 s
    writer.close()
    for _, w in held:
        w.close()
    await wait_for(lambda: relay.pending_handshakes == 0 and len(relay.handshakes_by_ip) == 0)


async def test_open_streams_are_limited_per_address(relay_factory):
    relay = await relay_factory(max_streams_per_ip=1, stream_open_timeout=3)
    a = await register(relay)
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        r1, w1 = await asyncio.open_connection("127.0.0.1", relay.public_port)
        w1.write(client_hello(a["name"]))
        await w1.drain()
        assert json.loads(await asyncio.wait_for(ctl.recv(), 5))["type"] == "open"
        r2, w2 = await asyncio.open_connection("127.0.0.1", relay.public_port)
        w2.write(client_hello(a["name"]))
        await w2.drain()
        assert await asyncio.wait_for(r2.read(), 1) == b""
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(ctl.recv(), 0.3)  # no second open
        w1.close()
        w2.close()
        await wait_for(lambda: relay.total_streams == 0 and len(relay.streams_by_ip) == 0, 10)


async def test_silent_broker_stream_ends_after_the_first_byte_timeout(relay_factory):
    relay = await relay_factory(stream_first_byte_timeout=0.3, stream_idle_timeout=30)
    a = await register(relay)
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
        writer.write(client_hello(a["name"]))
        await writer.drain()
        sid = json.loads(await asyncio.wait_for(ctl.recv(), 5))["stream"]
        async with await stream_ws(relay, a["secret"], sid) as st:
            await st.recv()  # the ClientHello; the broker never answers
            assert await asyncio.wait_for(reader.read(), 3) == b""
        writer.close()


async def test_control_connections_are_limited_per_address(relay_factory):
    relay = await relay_factory(max_control_connections_per_ip=2, conn_burst_per_ip=100)
    held = []
    for _ in range(2):
        held.append(await asyncio.open_connection(
            "127.0.0.1", relay.public_port, ssl=control_client_context(), server_hostname="relay.akdbx.link"))
    await wait_for(lambda: relay.control_connections == 2)
    with pytest.raises((ConnectionError, ssl.SSLError, OSError)):
        r, w = await asyncio.open_connection(
            "127.0.0.1", relay.public_port, ssl=control_client_context(), server_hostname="relay.akdbx.link")
        await asyncio.wait_for(r.read(), 2)
        raise ConnectionError("closed")  # read() returned: the connection was closed
    for _, w in held:
        w.close()
    await wait_for(lambda: relay.control_connections == 0)


# R9: one deadline over queue wait and ACME order


async def test_certificate_request_has_one_deadline(relay_factory):
    class SlowIssuer(FakeIssuer):
        async def issue(self, name, csr_pem_bytes, deadline=None):
            self.deadlines.append(deadline)
            await asyncio.sleep(5)
            return await FakeIssuer.issue(self, name, csr_pem_bytes)

    issuer = SlowIssuer()
    relay = await relay_factory(issuer, certificate_deadline=1.0, max_concurrent_issuance=1)
    a = await register(relay)
    b = await register(relay)

    async def cert(reg):
        return await api(relay, "POST", "/api/v1/certificate", {"csr": csr_pem(make_csr(reg["name"]))},
                         {"Authorization": f"Bearer {reg['secret']}"})

    loop = asyncio.get_running_loop()
    start = loop.time()
    first = asyncio.create_task(cert(a))
    await wait_for(lambda: issuer.deadlines)
    second = await cert(b)  # waits for the only slot, then gives up inside the deadline
    assert second[0] == 503 and second[2]["error"] == "issuance_paused"
    status, _, body = await first
    assert status == 502 and body["error"] == "acme_failed"
    assert loop.time() - start < 2.5
    assert issuer.deadlines[0] is not None and issuer.deadlines[0] - start <= 1.1
    assert relay.store.broker_certificates_this_week(a["broker_id"]) == []


async def test_certificate_deadline_is_passed_to_the_issuer(relay_factory):
    issuer = FakeIssuer()
    relay = await relay_factory(issuer, certificate_deadline=30.0)
    a = await register(relay)
    loop = asyncio.get_running_loop()
    status, _, _ = await api(relay, "POST", "/api/v1/certificate", {"csr": csr_pem(make_csr(a["name"]))},
                             {"Authorization": f"Bearer {a['secret']}"})
    assert status == 200
    assert 25 < issuer.deadlines[-1] - loop.time() <= 30


# Shutdown


async def test_stop_closes_control_connections(tmp_path):
    relay = await start_relay(tmp_path)
    a = await register(relay)
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        await asyncio.wait_for(relay.stop(), 10)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(ctl.recv(), 5)
        assert ctl.close_code in (1001, 1006)
    relay.store.close()


def test_ca_helper_is_distinct():
    # Guard: the managed-certificate tests rely on a CA other than the operator test CA.
    assert CA().pem != CA().pem
