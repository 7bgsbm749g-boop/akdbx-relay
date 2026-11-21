"""End to end: phone TLS client -> relay :8443 -> broker WebSocket -> local TLS server."""

import asyncio
import contextlib
import json
import ssl

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from akdbx_relay.testclient import BrokerClient, register

from .helpers import CA, client_hello, client_kw, control_client_context, relay_url

PAGE = b"secret page body: only the broker can decrypt this"


async def start_tls_page(ca: CA, name: str, tmp_path):
    chain, key = ca.leaf(name)
    (tmp_path / "chain.pem").write_bytes(chain)
    (tmp_path / "key.pem").write_bytes(key)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / "chain.pem", tmp_path / "key.pem")
    seen_hosts = []

    async def handle(reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            seen_hosts.append(head)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(PAGE), PAGE))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1], seen_hosts


async def https_get(port: int, name: str, ca: CA, timeout=10) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port, ssl=ca.client_context(), server_hostname=name), timeout
    )
    writer.write(f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout)
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return data


async def closed_without_data(port: int, payload: bytes, timeout=5) -> bool:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with contextlib.suppress(ConnectionError):
        writer.write(payload)
        await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(), timeout)
    except ConnectionError:
        data = b""
    writer.close()
    return data == b""


@pytest.fixture
def ca():
    return CA()


async def setup_broker(relay, ca, tmp_path):
    url = relay_url(relay)
    reg = await register(url, **client_kw())
    server, local_port, seen = await start_tls_page(ca, reg["name"], tmp_path)
    client = BrokerClient(url, reg["secret"], local_port, **client_kw())
    task = asyncio.create_task(client.run())
    await asyncio.wait_for(client.connected.wait(), 5)
    for _ in range(100):
        if reg["broker_id"] in relay.controls:
            break
        await asyncio.sleep(0.01)
    return reg, client, task, server, seen


async def teardown(client, task, server):
    await client.stop()
    task.cancel()
    with contextlib.suppress(BaseException):
        await task
    server.close()


async def test_end_to_end_https_through_relay(relay_factory, ca, tmp_path):
    # Phones and the broker's stream connections all come from 127.0.0.1 and
    # share the per-address limits on :8443; this test opens ~30 at once.
    relay = await relay_factory(conn_burst_per_ip=100, max_handshakes_per_ip=32)
    reg, client, task, server, seen = await setup_broker(relay, ca, tmp_path)
    try:
        for _ in range(3):
            data = await https_get(relay.public_port, reg["name"], ca)
            assert data.startswith(b"HTTP/1.1 200 OK") and data.endswith(PAGE)
        assert client.streams_opened == 3
        assert len(seen) == 3 and all(reg["name"].encode() in h for h in seen)
        # Several connections at once.
        results = await asyncio.gather(*(https_get(relay.public_port, reg["name"], ca) for _ in range(10)))
        assert all(r.endswith(PAGE) for r in results)
        await asyncio.sleep(0.1)
        assert relay.total_streams == 0 and relay.streams_per_broker == {} and relay.pending == {}
    finally:
        await teardown(client, task, server)


async def test_unknown_names_and_offline_brokers_are_closed(relay_factory, ca, tmp_path):
    relay = await relay_factory()
    url = relay_url(relay)
    offline = await register(url, **client_kw())
    port = relay.public_port
    assert await closed_without_data(port, client_hello(offline["name"]))  # no control channel
    assert await closed_without_data(port, client_hello("zzzzzzzzzzzz.akdbx.link"))  # unknown
    assert await closed_without_data(port, client_hello("www.akdbx.link"))  # reserved
    assert await closed_without_data(port, client_hello("example.com"))
    assert await closed_without_data(port, client_hello(None))  # no SNI
    assert await closed_without_data(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")  # not TLS


async def test_client_hello_timeout_closes(relay_factory):
    relay = await relay_factory(client_hello_timeout=0.3)
    reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
    writer.write(client_hello("abcdefghijkl.akdbx.link")[:10])
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 3)
    assert data == b""
    writer.close()


def _wss(relay, path, secret):
    return connect(f"wss://{relay.cfg.control_hostname}:{relay.public_port}{path}",
                   additional_headers={"Authorization": f"Bearer {secret}"},
                   ssl=control_client_context(), host="127.0.0.1")


async def control(relay, secret):
    return _wss(relay, "/api/v1/connect", secret)


async def stream_ws(relay, secret, stream_id):
    return _wss(relay, f"/api/v1/stream/{stream_id}", secret)


async def wait_for(predicate, timeout=5.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        if loop.time() > end:
            raise AssertionError("condition not met")
        await asyncio.sleep(0.01)


async def test_stream_ids_are_single_use_and_bound_to_the_broker(relay_factory):
    relay = await relay_factory()
    url = relay_url(relay)
    a = await register(url, **client_kw())
    b = await register(url, **client_kw())
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
        hello = client_hello(a["name"])
        writer.write(hello)
        await writer.drain()
        msg = json.loads(await asyncio.wait_for(ctl.recv(), 5))
        assert msg["type"] == "open" and len(msg["stream"]) == 32
        sid = msg["stream"]
        # Another broker cannot take the stream.
        with pytest.raises(InvalidStatus) as exc:
            async with await stream_ws(relay, b["secret"], sid):
                pass
        assert exc.value.response.status_code == 404
        # A bad secret cannot either.
        with pytest.raises(InvalidStatus) as exc:
            async with await stream_ws(relay, "x" * 43, sid):
                pass
        assert exc.value.response.status_code == 401
        async with await stream_ws(relay, a["secret"], sid) as st:
            first = await asyncio.wait_for(st.recv(), 5)
            assert first == hello  # the buffered ClientHello is replayed unchanged
            # Second use of the same id fails.
            with pytest.raises(InvalidStatus) as exc:
                async with await stream_ws(relay, a["secret"], sid):
                    pass
            assert exc.value.response.status_code == 404
            # Bytes flow both ways, unchanged.
            await st.send(b"\x16\x03\x03from-broker")
            assert await asyncio.wait_for(reader.readexactly(14), 5) == b"\x16\x03\x03from-broker"
            writer.write(b"from-phone")
            await writer.drain()
            assert await asyncio.wait_for(st.recv(), 5) == b"from-phone"
            # Closing the phone side ends the stream.
            writer.close()
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(st.recv(), 5)


async def test_text_frame_on_stream_is_protocol_error(relay_factory):
    relay = await relay_factory()
    a = await register(relay_url(relay), **client_kw())
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
        writer.write(client_hello(a["name"]))
        await writer.drain()
        sid = json.loads(await asyncio.wait_for(ctl.recv(), 5))["stream"]
        async with await stream_ws(relay, a["secret"], sid) as st:
            await st.recv()
            await st.send("text is not allowed")
            with pytest.raises(ConnectionClosed) as exc:
                await asyncio.wait_for(st.recv(), 5)
            assert exc.value.rcvd.code == 1003
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()


async def test_stream_open_timeout(relay_factory):
    relay = await relay_factory(stream_open_timeout=0.3)
    a = await register(relay_url(relay), **client_kw())
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
        writer.write(client_hello(a["name"]))
        await writer.drain()
        sid = json.loads(await asyncio.wait_for(ctl.recv(), 5))["stream"]
        assert await asyncio.wait_for(reader.read(), 5) == b""  # broker never came
        with pytest.raises(InvalidStatus) as exc:
            async with await stream_ws(relay, a["secret"], sid):
                pass
        assert exc.value.response.status_code == 404
        assert relay.pending == {} and relay.total_streams == 0


async def test_stream_idle_timeout(relay_factory):
    relay = await relay_factory(stream_idle_timeout=0.4)
    a = await register(relay_url(relay), **client_kw())
    async with await control(relay, a["secret"]) as ctl:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        reader, writer = await asyncio.open_connection("127.0.0.1", relay.public_port)
        writer.write(client_hello(a["name"]))
        await writer.drain()
        sid = json.loads(await asyncio.wait_for(ctl.recv(), 5))["stream"]
        async with await stream_ws(relay, a["secret"], sid) as st:
            await st.recv()
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(st.recv(), 5)
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()


async def test_per_broker_and_global_stream_caps(relay_factory):
    relay = await relay_factory(max_streams_per_broker=2, max_streams_total=3, stream_open_timeout=1.5)
    url = relay_url(relay)
    a = await register(url, **client_kw())
    b = await register(url, **client_kw())
    async with await control(relay, a["secret"]) as ca_, await control(relay, b["secret"]) as cb:
        await wait_for(lambda: a["broker_id"] in relay.controls and b["broker_id"] in relay.controls)
        conns = []
        for _ in range(2):
            r, w = await asyncio.open_connection("127.0.0.1", relay.public_port)
            w.write(client_hello(a["name"]))
            conns.append((r, w))
        await wait_for(lambda: relay.streams_per_broker.get(a["broker_id"]) == 2)
        # A third stream for broker a is refused.
        assert await closed_without_data(relay.public_port, client_hello(a["name"]))
        r, w = await asyncio.open_connection("127.0.0.1", relay.public_port)
        w.write(client_hello(b["name"]))
        conns.append((r, w))
        await wait_for(lambda: relay.total_streams == 3)
        # The global cap refuses broker b's second stream.
        assert await closed_without_data(relay.public_port, client_hello(b["name"]))
        for _, w in conns:
            w.close()
        await wait_for(lambda: relay.total_streams == 0, 10)


async def test_connection_rate_limit_per_ip(relay_factory):
    relay = await relay_factory(conn_rate_per_ip=0.1, conn_burst_per_ip=2, client_hello_timeout=5)
    opened = []
    for _ in range(2):
        r, w = await asyncio.open_connection("127.0.0.1", relay.public_port)
        opened.append((r, w))
    await asyncio.sleep(0.05)
    # The third connection is closed at once, before any ClientHello.
    r, w = await asyncio.open_connection("127.0.0.1", relay.public_port)
    assert await asyncio.wait_for(r.read(), 1) == b""
    assert relay.pending_handshakes == 2
    for _, wr in opened:
        wr.close()


async def test_control_ping_pong_and_timeout(relay_factory):
    relay = await relay_factory(control_ping_interval=0.1, control_pong_timeout=0.4)
    a = await register(relay_url(relay), **client_kw())
    async with await control(relay, a["secret"]) as ctl:
        # Answer two pings, then go silent.
        for _ in range(2):
            assert json.loads(await asyncio.wait_for(ctl.recv(), 2)) == {"type": "ping"}
            await ctl.send('{"type":"pong"}')
        with pytest.raises(ConnectionClosed) as exc:
            while True:
                await asyncio.wait_for(ctl.recv(), 3)
        assert exc.value.rcvd.code == 4001
    await wait_for(lambda: a["broker_id"] not in relay.controls)


async def test_answering_client_stays_connected(relay_factory, ca, tmp_path):
    relay = await relay_factory(control_ping_interval=0.05, control_pong_timeout=0.3)
    reg, client, task, server, _ = await setup_broker(relay, ca, tmp_path)
    try:
        await asyncio.sleep(1.0)
        assert reg["broker_id"] in relay.controls and client.connected.is_set()
        assert (await https_get(relay.public_port, reg["name"], ca)).endswith(PAGE)
    finally:
        await teardown(client, task, server)


async def test_new_control_connection_replaces_old(relay_factory):
    relay = await relay_factory()
    a = await register(relay_url(relay), **client_kw())
    async with await control(relay, a["secret"]) as first:
        await wait_for(lambda: a["broker_id"] in relay.controls)
        old = relay.controls[a["broker_id"]]
        async with await control(relay, a["secret"]) as second:
            await wait_for(lambda: relay.controls.get(a["broker_id"]) is not old)
            with pytest.raises(ConnectionClosed) as exc:
                await asyncio.wait_for(first.recv(), 5)
            assert exc.value.rcvd.code == 4000
            await second.send('{"type":"ping"}')
            assert json.loads(await asyncio.wait_for(second.recv(), 5)) == {"type": "pong"}
            assert a["broker_id"] in relay.controls


async def test_binary_on_control_channel_closes_it(relay_factory):
    relay = await relay_factory()
    a = await register(relay_url(relay), **client_kw())
    async with await control(relay, a["secret"]) as ctl:
        await ctl.send(b"\x00\x01")
        with pytest.raises(ConnectionClosed) as exc:
            await asyncio.wait_for(ctl.recv(), 5)
        assert exc.value.rcvd.code == 1003


async def test_control_requires_auth(relay_factory):
    relay = await relay_factory()
    with pytest.raises(InvalidStatus) as exc:
        async with await control(relay, "y" * 43):
            pass
    assert exc.value.response.status_code == 401


async def test_broker_reconnects_after_relay_drop(relay_factory, ca, tmp_path):
    relay = await relay_factory()
    reg, client, task, server, _ = await setup_broker(relay, ca, tmp_path)
    try:
        await relay.controls[reg["broker_id"]].ws.close(1011, "test drop")
        await wait_for(lambda: not client.connected.is_set(), 5)
        await asyncio.wait_for(client.connected.wait(), 5)
        await wait_for(lambda: reg["broker_id"] in relay.controls)
        assert (await https_get(relay.public_port, reg["name"], ca)).endswith(PAGE)
    finally:
        await teardown(client, task, server)


async def test_large_transfer(relay_factory, ca, tmp_path):
    relay = await relay_factory()
    url = relay_url(relay)
    reg = await register(url, **client_kw())
    chain, key = ca.leaf(reg["name"])
    (tmp_path / "c.pem").write_bytes(chain)
    (tmp_path / "k.pem").write_bytes(key)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    blob = bytes(range(256)) * 8192  # 2 MiB

    async def echo(reader, writer):
        n = int((await reader.readline()).strip())
        got = await reader.readexactly(n)
        writer.write(got)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0, ssl=ctx)
    client = BrokerClient(url, reg["secret"], server.sockets[0].getsockname()[1], **client_kw())
    task = asyncio.create_task(client.run())
    try:
        await asyncio.wait_for(client.connected.wait(), 5)
        await wait_for(lambda: reg["broker_id"] in relay.controls)
        r, w = await asyncio.open_connection("127.0.0.1", relay.public_port, ssl=ca.client_context(),
                                             server_hostname=reg["name"])
        w.write(b"%d\n" % len(blob) + blob)
        await w.drain()
        assert await asyncio.wait_for(r.readexactly(len(blob)), 20) == blob
        w.close()
    finally:
        await teardown(client, task, server)
