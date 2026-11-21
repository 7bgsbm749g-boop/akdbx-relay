"""Connection and file lifecycles: slots released after a stalled TLS bridge,
atomic key files, the certificate log for the control certificate, separate
connection buckets for the control host, slow phones, and TXT-record cleanup
that never holds a response past its deadline."""

import asyncio
import base64
import datetime
import json
import os
import socket

import pytest

from akdbx_relay import controltls, issuer as issuer_mod, wsconn
from akdbx_relay.issuer import RECORD_COMMENT
from akdbx_relay.relay import CONTROL_CERT_ID, CONTROL_DRAIN_TIMEOUT

from .fakes import FakeACME, FakeCloudflare
from .helpers import (
    CONTROL_HOSTNAME,
    FakeIssuer,
    api,
    client_hello,
    control_client_context,
    csr_pem,
    make_csr,
    start_relay,
)
from .test_acme import NAME, make_issuer
from .test_e2e import PAGE, ca, closed_without_data, control, https_get, setup_broker, stream_ws, teardown, wait_for

__all__ = ["ca"]  # pytest fixture re-exported from test_e2e


@pytest.fixture
def fakes():
    cf = FakeCloudflare().start()
    acme = FakeACME(cf).start()
    yield acme, cf
    acme.stop()
    cf.stop()


async def register(relay):
    status, _, body = await api(relay, "POST", "/api/v1/register", {"protocol": 1})
    assert status == 201, body
    return body


async def small_buffer_connection(port: int, rcvbuf: int = 4096, **kw):
    """A TCP connection to 127.0.0.1:port with a small receive buffer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    sock.setblocking(False)
    await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", port))
    reader, writer = await asyncio.open_connection(sock=sock, **kw)
    return sock, reader, writer


# The TLS bridge releases its slots when the relay's TLS session ends while
# the broker has stopped reading.


async def test_control_slots_are_released_when_the_session_ends_and_the_peer_stops_reading(
        relay_factory, monkeypatch):
    monkeypatch.setattr(wsconn, "CLOSE_TIMEOUT", 0.5)
    relay = await relay_factory(stream_first_byte_timeout=0.5, stream_idle_timeout=30)
    a = await register(relay)
    loop = asyncio.get_running_loop()
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        _, phone_r, phone_w = await small_buffer_connection(relay.public_port)
        phone_w.write(client_hello(a["name"]))
        await phone_w.drain()
        sid = json.loads(await asyncio.wait_for(ctl.recv(), 5))["stream"]
        # The broker opens the stream WebSocket over TLS, then never reads again.
        _, br, bw = await small_buffer_connection(
            relay.public_port, ssl=control_client_context(), server_hostname=CONTROL_HOSTNAME, limit=4096)
        key = base64.b64encode(os.urandom(16)).decode()
        bw.write((f"GET /api/v1/stream/{sid} HTTP/1.1\r\nHost: {CONTROL_HOSTNAME}\r\n"
                  f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                  f"Sec-WebSocket-Version: 13\r\nAuthorization: Bearer {a['secret']}\r\n\r\n").encode())
        head = await asyncio.wait_for(br.readuntil(b"\r\n\r\n"), 5)
        assert b" 101 " in head.split(b"\r\n", 1)[0]
        assert relay.control_connections == 2
        # The phone sends far more than the buffers on the way to the broker hold.
        phone_w.write(b"\x17" * (16 << 20))
        # The broker never answers: the stream ends after the first-byte
        # timeout, and with it the relay's TLS session for the stream.
        await wait_for(lambda: relay.total_streams == 0, 10)
        start = loop.time()
        await wait_for(lambda: relay.control_connections == 1, CONTROL_DRAIN_TIMEOUT + 3)
        assert loop.time() - start <= CONTROL_DRAIN_TIMEOUT + 3
        assert relay.control_by_ip.get("127.0.0.1") == 1  # only the control channel
        phone_w.close()
        bw.close()


async def test_control_slots_are_released_when_the_socket_pair_fails(relay_factory, monkeypatch):
    relay = await relay_factory()

    def no_socketpair(*args, **kwargs):
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(socket, "socketpair", no_socketpair)
    assert await closed_without_data(relay.public_port, client_hello(CONTROL_HOSTNAME))
    await wait_for(lambda: relay.control_connections == 0 and len(relay.control_by_ip) == 0, 2)


# Key and chain files are written atomically


def test_control_key_and_chain_writes_are_atomic(tmp_path, monkeypatch):
    state = tmp_path / "state"
    key_path = state / "control-key.pem"
    chain_path = state / "control-chain.pem"
    real_fdopen = os.fdopen

    class TornFile:
        """Writes half of the data, then fails (a full disk or a crash)."""

        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.fh.close()

        def write(self, data):
            self.fh.write(data[: len(data) // 2])
            self.fh.flush()
            raise OSError(28, "No space left on device")

        def flush(self):
            self.fh.flush()

        def fileno(self):
            return self.fh.fileno()

    monkeypatch.setattr(os, "fdopen", lambda fd, *a, **k: TornFile(real_fdopen(fd, *a, **k)))
    with pytest.raises(OSError):
        controltls.load_or_create_key(str(key_path))
    state.mkdir(exist_ok=True)
    chain_path.write_bytes(b"old chain")
    with pytest.raises(OSError):
        controltls.write_private(str(chain_path), b"new chain " * 100)
    monkeypatch.undo()
    # No partial key at the final path, the old chain intact, no temporary files.
    assert not key_path.exists()
    assert chain_path.read_bytes() == b"old chain"
    assert sorted(p.name for p in state.iterdir()) == ["control-chain.pem"]
    # The next start makes a complete private key.
    key = controltls.load_or_create_key(str(key_path))
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert controltls.load_or_create_key(str(key_path)).private_numbers() == key.private_numbers()
    assert sorted(p.name for p in state.iterdir()) == ["control-chain.pem", "control-key.pem"]


# Control certificates are in the certificate log


async def test_control_certificate_orders_are_recorded_in_the_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(controltls, "RETRY_MIN", 0.05)
    monkeypatch.setattr(controltls, "CHECK_MAX", 0.05)
    issuer = FakeIssuer()
    relay = await start_relay(tmp_path, issuer, managed_tls=True)

    def rows():
        return [r[0] for r in relay.store.db.execute(
            "SELECT first_time FROM certificates WHERE broker_id = ? ORDER BY id", (CONTROL_CERT_ID,))]

    try:
        await wait_for(lambda: relay.control_tls.context is not None and rows())
        assert rows() == [1]
        assert relay.budget.status()["first_time_certificates_7d"] == 1
        # A renewal of the same name is logged, but is not a new certificate.
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=61)
        relay.control_tls._now = lambda: later
        await wait_for(lambda: len(rows()) >= 2)
        assert rows()[0] == 1 and set(rows()[1:]) == {0}
        assert len(relay.store.first_time_certificates()) == 1
    finally:
        await relay.stop()
        relay.store.close()


# The control host name has its own connection bucket


async def test_broker_and_browser_behind_one_address(relay_factory, ca, tmp_path):
    # Default connection rate (10/s, burst 20). The browser opens 15
    # connections and the broker 15 stream connections plus its control
    # channel and registration: about 30 from one address.
    relay = await relay_factory(max_handshakes_per_ip=64)
    assert relay.cfg.conn_burst_per_ip == 20 and relay.cfg.conn_rate_per_ip == 10
    reg, client, task, server, _ = await setup_broker(relay, ca, tmp_path)
    try:
        results = await asyncio.gather(*(https_get(relay.public_port, reg["name"], ca) for _ in range(15)),
                                       return_exceptions=True)
        assert all(isinstance(r, bytes) and r.endswith(PAGE) for r in results), results
        assert client.streams_opened == 15
    finally:
        await teardown(client, task, server)


def test_control_bucket_default_covers_a_burst_of_streams():
    from akdbx_relay.config import Config

    cfg = Config.from_env({})
    assert cfg.control_conn_burst_per_ip > cfg.max_streams_per_broker
    cfg = Config.from_env({"AKDBX_RELAY_CONTROL_CONN_RATE_PER_IP": "5",
                           "AKDBX_RELAY_CONTROL_CONN_BURST_PER_IP": "200"})
    assert (cfg.control_conn_rate_per_ip, cfg.control_conn_burst_per_ip) == (5.0, 200)


# A slow phone gets every byte after a normal stream end


async def test_slow_phone_receives_every_byte_after_the_stream_ends(relay_factory):
    relay = await relay_factory()
    a = await register(relay)
    payload = os.urandom(48 * 1024)
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        sock, reader, writer = await small_buffer_connection(relay.public_port, limit=4096)
        writer.write(client_hello(a["name"]))
        await writer.drain()
        sid = json.loads(await asyncio.wait_for(ctl.recv(), 5))["stream"]
        # Small kernel buffers on the relay's side as well, so most of the
        # data waits in the relay's own write buffer.
        relay_side = next(w for w in relay._public_writers
                          if w.get_extra_info("peername") == sock.getsockname())
        relay_side.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        async with await stream_ws(relay, a["secret"], sid) as st:
            await st.recv()  # the ClientHello
            await st.send(payload)
        # The broker closed the stream; the phone reads nothing for longer
        # than the short close limit of error paths (2 s).
        await wait_for(lambda: relay.total_streams == 0, 5)
        await asyncio.sleep(3)
        got = await asyncio.wait_for(reader.read(), 10)
        assert len(got) == len(payload) and got == payload
        writer.close()


# Start-up TXT markers whose create call may still land


async def test_young_marker_without_a_record_is_kept_and_rechecked(tmp_path, fakes):
    acme, cf = fakes
    cfg, store, issuer = make_issuer(tmp_path, acme, cf)
    window = issuer_mod.STALE_RECORD_AGE_FACTOR * cfg.certificate_deadline
    record = "_acme-challenge." + NAME
    young = store.add_txt_marker(record, "late-value")  # create cut off; not in the zone yet
    old = store.add_txt_marker(record, "old-value")
    store.db.execute("UPDATE acme_txt_markers SET created_at = created_at - ? WHERE id = ?",
                     (window + 60, old.id))
    delay = await issuer.cleanup_stale_records()
    assert [m.id for m in store.txt_markers()] == [young.id]
    assert delay is not None and window - 10 < delay <= window + 1.5
    # The cut-off create lands after the start-up lookup; the zone sweep
    # would skip it as too new. The recheck finds it through the marker.
    rid = cf.add_record(record, "late-value", RECORD_COMMENT)
    other = store.add_txt_marker(record, "running-order")  # an order of this process
    await issuer.recheck_markers()
    assert rid not in cf.records
    assert [m.id for m in store.txt_markers()] == [other.id]
    store.close()


async def test_relay_runs_the_marker_recheck(relay_factory):
    class RecheckIssuer(FakeIssuer):
        rechecked = False

        async def cleanup_stale_records(self):
            return 0.05

        async def recheck_markers(self):
            self.rechecked = True

    issuer = RecheckIssuer()
    await relay_factory(issuer)
    await wait_for(lambda: issuer.rechecked, 2)


# The request deadline does not wait for the TXT delete


async def test_deadline_cancel_returns_in_time_and_removes_the_record_later(
        tmp_path, fakes, relay_factory, monkeypatch):
    monkeypatch.setattr(issuer_mod, "MIN_VALIDATION_SECONDS", 0.5)
    acme, cf = fakes
    cf.create_delay = 1.0  # starts the challenge answer late in the deadline
    acme.chall_delay = 3.0  # validation still running when the deadline passes
    cf.delete_delay = 2.0  # and the TXT delete is slow
    cfg, store, issuer = make_issuer(tmp_path / "issuer", acme, cf)
    relay = await relay_factory(issuer, certificate_deadline=2.5)
    issuer.store = relay.store
    issuer.cfg = relay.cfg
    relay.cfg.acme_directory = cfg.acme_directory
    relay.cfg.acme_account_key_file = cfg.acme_account_key_file
    a = await register(relay)
    loop = asyncio.get_running_loop()
    start = loop.time()
    status, _, body = await api(relay, "POST", "/api/v1/certificate", {"csr": csr_pem(make_csr(a["name"]))},
                                {"Authorization": f"Bearer {a['secret']}"})
    elapsed = loop.time() - start
    assert status == 502 and body["error"] == "acme_failed"
    assert elapsed < 2.5 + 0.8
    # The durable marker stays while the delete runs in the background.
    assert len(relay.store.txt_markers()) == 1 and len(cf.records) == 1
    await wait_for(lambda: cf.records == {} and relay.store.txt_markers() == [], 10)
    store.close()
