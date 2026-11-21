"""ServerWebSocket limits: fragments (R2), bounded close (R3), keepalive (R10)."""

import asyncio
import contextlib
import socket

import pytest
from websockets.client import ClientProtocol
from websockets.frames import Close
from websockets.uri import parse_uri

from akdbx_relay import wsconn
from akdbx_relay.wsconn import ServerWebSocket


class RawClient:
    """A WebSocket client on the sans-I/O protocol that reads only when asked."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.proto = ClientProtocol(parse_uri("ws://127.0.0.1/"), max_size=None)

    async def handshake(self):
        self.proto.send_request(self.proto.connect())
        await self.flush()
        while not self.proto.events_received() and self.proto.handshake_exc is None:
            data = await asyncio.wait_for(self.reader.read(65536), 5)
            assert data
            self.proto.receive_data(data)

    async def flush(self):
        for data in self.proto.data_to_send():
            if data:
                self.writer.write(data)
        await self.writer.drain()

    async def close_code(self, timeout=3.0):
        """Read until the server's closing frame (or EOF); return its code."""
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while True:
            data = await asyncio.wait_for(self.reader.read(65536), end - loop.time())
            if not data:
                return self.proto.close_rcvd.code if self.proto.close_rcvd else None
            self.proto.receive_data(data)
            for event in self.proto.events_received():
                if event.opcode.name == "CLOSE":
                    return Close.parse(event.data).code


@pytest.fixture
async def ws_pair(monkeypatch):
    """Factory: (server ServerWebSocket, RawClient) over a real local socket."""
    # The raw client does not answer closing frames; keep closes short.
    monkeypatch.setattr(wsconn, "CLOSE_TIMEOUT", 0.3, raising=False)
    servers = []
    accepted: asyncio.Queue = asyncio.Queue()

    async def make(max_size=256 * 1024, max_queue=16, small_buffers=False):
        async def handle(reader, writer):
            if small_buffers:
                writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                writer.transport.set_write_buffer_limits(high=4096)
            head = await reader.readuntil(b"\r\n\r\n")
            ws = await ServerWebSocket.accept(reader, writer, head, max_size, max_queue)
            await accepted.put(ws)
            if ws is not None:
                await ws.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        servers.append(server)
        port = server.sockets[0].getsockname()[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if small_buffers:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", port))
        reader, writer = await asyncio.open_connection(sock=sock)
        client = RawClient(reader, writer)
        await client.handshake()
        ws = await asyncio.wait_for(accepted.get(), 5)
        return ws, client

    yield make
    for server in servers:
        server.close()


# R2: fragments


async def test_fragmented_message_is_delivered(ws_pair):
    ws, client = await ws_pair()
    client.proto.send_binary(b"ab", fin=False)
    client.proto.send_continuation(b"", fin=False)
    client.proto.send_continuation(b"cd", fin=True)
    await client.flush()
    assert await asyncio.wait_for(ws.recv(), 3) == b"abcd"
    await ws.close()


async def test_empty_fragments_are_capped(ws_pair):
    # R2: one unfinished message made of thousands of empty fragments used to
    # grow a list without limit; now the connection fails with 1009.
    ws, client = await ws_pair()
    client.proto.send_binary(b"a", fin=False)
    for _ in range(3000):
        client.proto.send_continuation(b"", fin=False)
    await client.flush()
    assert await client.close_code() == 1009
    assert len(ws._fragments) == 0


async def test_fragments_beyond_max_size_fail(ws_pair):
    ws, client = await ws_pair(max_size=1000)
    client.proto.send_binary(b"x" * 600, fin=False)
    client.proto.send_continuation(b"y" * 600, fin=True)
    await client.flush()
    assert await client.close_code() == 1009


# R3: bounded close


async def test_close_is_bounded_when_peer_stops_reading(ws_pair, monkeypatch):
    # R3: close used to wait for the write buffer to drain before its own
    # timeout started; a peer that never reads held it open forever.
    monkeypatch.setattr(wsconn, "CLOSE_TIMEOUT", 0.5, raising=False)
    ws, client = await ws_pair(small_buffers=True)

    async def flood():
        while True:
            await ws.send(b"z" * 65536)

    sender = asyncio.create_task(flood())
    loop = asyncio.get_running_loop()
    end = loop.time() + 5
    while ws.writer.transport.get_write_buffer_size() <= 4096:  # the peer stopped reading
        assert loop.time() < end
        await asyncio.sleep(0.02)
    sender.cancel()
    with contextlib.suppress(BaseException):
        await sender
    start = loop.time()
    await asyncio.wait_for(ws.close(), 3)
    assert loop.time() - start < 2
    assert ws.writer.transport.is_closing()
    assert not ws.open
    client.writer.close()


# R10: keepalive


async def test_keepalive_tolerates_a_full_receive_queue(ws_pair):
    # R10: while the relay is not reading (queue full), a pong cannot be seen;
    # that must not fail the stream.
    ws, client = await ws_pair(max_queue=2)
    for _ in range(5):
        client.proto.send_binary(b"data")
    await client.flush()
    ws.start_keepalive(0.1, 0.2)
    await asyncio.sleep(1.0)
    assert ws.open
    for _ in range(5):
        assert await asyncio.wait_for(ws.recv(), 2) == b"data"
    await ws.close()


async def test_keepalive_counts_received_data_as_alive(ws_pair):
    # R10: a peer that sends data but whose pongs are not seen stays connected.
    ws, client = await ws_pair()
    ws.start_keepalive(0.1, 0.2)
    got = []

    async def consume():
        while True:
            got.append(await ws.recv())

    consumer = asyncio.create_task(consume())
    for _ in range(20):
        client.proto.send_binary(b"tick")
        await client.flush()
        await asyncio.sleep(0.05)
    assert ws.open and len(got) == 20
    consumer.cancel()
    await ws.close()


async def test_keepalive_closes_a_silent_peer(ws_pair):
    ws, client = await ws_pair()
    ws.start_keepalive(0.1, 0.2)
    await asyncio.wait_for(ws.wait_closed(), 3)
    assert not ws.open
