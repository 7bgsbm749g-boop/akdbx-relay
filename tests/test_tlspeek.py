import asyncio
import random
import struct

import pytest

from akdbx_relay.tlspeek import (
    ClientHelloError,
    NeedMoreData,
    parse_client_hello,
    read_client_hello,
)

from .helpers import client_hello

NAME = "abcdefghijkl.akdbx.link"


def split_records(hello: bytes, sizes: list[int]) -> bytes:
    """Re-fragment a single-record ClientHello into several handshake records."""
    assert hello[0] == 22
    version = hello[1:3]
    payload = hello[5:]
    out = b""
    pos = 0
    for size in sizes + [len(payload)]:
        chunk = payload[pos : pos + size]
        if not chunk:
            break
        out += bytes([22]) + version + struct.pack(">H", len(chunk)) + chunk
        pos += len(chunk)
    return out


def build_hello(extensions: bytes, *, body_extra: bytes = b"") -> bytes:
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions + body_extra
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def sni_ext(*names: tuple[int, bytes]) -> bytes:
    entries = b"".join(bytes([t]) + struct.pack(">H", len(n)) + n for t, n in names)
    data = struct.pack(">H", len(entries)) + entries
    return struct.pack(">HH", 0, len(data)) + data


@pytest.mark.parametrize("tls13", [True, False])
def test_real_client_hello(tls13):
    hello = client_hello(NAME, tls13=tls13)
    assert parse_client_hello(hello) == NAME


def test_no_sni():
    assert parse_client_hello(client_hello(None)) is None


def test_upper_case_and_trailing_dot_are_normalised():
    assert parse_client_hello(build_hello(sni_ext((0, b"ABCDEFGHIJKL.akdbx.link.")))) == NAME


def test_fragmented_across_records():
    hello = client_hello(NAME)
    for sizes in ([1], [3], [4, 1], [10, 10, 10], [100]):
        assert parse_client_hello(split_records(hello, sizes)) == NAME


def test_incremental_bytes_need_more_until_complete():
    hello = split_records(client_hello(NAME), [7, 50])
    for i in range(1, len(hello)):
        with pytest.raises(NeedMoreData):
            parse_client_hello(hello[:i])
    assert parse_client_hello(hello) == NAME


def test_trailing_bytes_after_hello_are_ignored():
    hello = client_hello(NAME)
    assert parse_client_hello(hello + b"\x17\x03\x03\x00\x05hello") == NAME


@pytest.mark.parametrize(
    "data",
    [
        b"GET / HTTP/1.1\r\n\r\n",
        b"\x80\x2e\x01\x03\x01",  # SSLv2-style hello
        b"\x17\x03\x03\x00\x05hello",  # application data first
        b"\x16\x02\x00\x00\x05aaaaa",  # bad record version
        b"\x16\x03\x01\x00\x00",  # empty record
        b"\x16\x03\x01\x40\x01" + b"\x00" * 10,  # record above 2^14
        b"\x16\x03\x01\x00\x04\x02\x00\x00\x00",  # ServerHello, not ClientHello
    ],
)
def test_rejects_non_client_hello(data):
    with pytest.raises(ClientHelloError):
        parse_client_hello(data)


def test_size_limit():
    hs = b"\x01" + (20000).to_bytes(3, "big")
    with pytest.raises(ClientHelloError):
        parse_client_hello(b"\x16\x03\x01\x00\x04" + hs)
    # Many records that never complete the message: stops at the byte limit.
    big = b"".join(b"\x16\x03\x01\x10\x00" + b"\x01\x00\x7f\xff" + b"\x00" * 4092 for _ in range(1))
    with pytest.raises((ClientHelloError, NeedMoreData)):
        parse_client_hello(big, max_bytes=4096)


@pytest.mark.parametrize(
    "ext",
    [
        sni_ext((0, b"a" * 64 + b".akdbx.link")),  # label too long
        sni_ext((0, b"bad_label.akdbx.link")),
        sni_ext((0, "zä.akdbx.link".encode())),
        sni_ext((0, b"")),
        sni_ext((0, NAME.encode()), (0, b"other.akdbx.link")),
        sni_ext(),
        sni_ext((0, NAME.encode())) + sni_ext((0, NAME.encode())),  # duplicate extension
    ],
)
def test_bad_server_names(ext):
    with pytest.raises(ClientHelloError):
        parse_client_hello(build_hello(ext))


def test_unknown_name_type_is_skipped():
    assert parse_client_hello(build_hello(sni_ext((1, b"xx"), (0, NAME.encode())))) == NAME


def test_trailing_garbage_inside_hello():
    with pytest.raises(ClientHelloError):
        parse_client_hello(build_hello(sni_ext((0, NAME.encode())), body_extra=b"\x00"))


def test_fuzz_mutations_never_raise_unexpected_errors():
    rng = random.Random(1234)
    seeds = [client_hello(NAME), client_hello(NAME, tls13=False), client_hello(None),
             split_records(client_hello(NAME), [20, 30])]
    for _ in range(4000):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 8)):
            op = rng.random()
            pos = rng.randrange(len(data))
            if op < 0.5:
                data[pos] = rng.randrange(256)
            elif op < 0.75:
                del data[pos : pos + rng.randint(1, 16)]
            else:
                data[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
            if not data:
                data = bytearray(b"\x16")
        try:
            result = parse_client_hello(bytes(data))
        except (ClientHelloError, NeedMoreData):
            continue
        assert result is None or isinstance(result, str)


def test_fuzz_random_bytes():
    rng = random.Random(99)
    for _ in range(3000):
        n = rng.randint(0, 600)
        data = bytes(rng.randrange(256) for _ in range(n))
        if rng.random() < 0.5 and data:
            data = b"\x16\x03\x01" + data
        try:
            parse_client_hello(data)
        except (ClientHelloError, NeedMoreData):
            pass


class FeedReader:
    """Wrap asyncio.StreamReader to feed chunks with delays."""

    def __init__(self, chunks, delay=0.0, eof=True):
        self.reader = asyncio.StreamReader()
        self.chunks = chunks
        self.delay = delay
        self.eof = eof

    async def run(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            self.reader.feed_data(chunk)
        if self.eof:
            self.reader.feed_eof()


async def test_read_client_hello_in_pieces():
    hello = client_hello(NAME)
    pieces = [hello[i : i + 37] for i in range(0, len(hello), 37)]
    feed = FeedReader(pieces, 0.001, eof=False)
    task = asyncio.create_task(feed.run())
    buffered, sni = await read_client_hello(feed.reader)
    await task
    assert sni == NAME
    assert buffered == hello


async def test_read_client_hello_timeout():
    feed = FeedReader([client_hello(NAME)[:20]], eof=False)
    task = asyncio.create_task(feed.run())
    with pytest.raises((TimeoutError, asyncio.TimeoutError)):
        await read_client_hello(feed.reader, timeout=0.2)
    await task


async def test_read_client_hello_eof():
    feed = FeedReader([client_hello(NAME)[:20]], eof=True)
    task = asyncio.create_task(feed.run())
    with pytest.raises(EOFError):
        await read_client_hello(feed.reader)
    await task


async def test_read_client_hello_too_large():
    hs = b"\x01" + (3000).to_bytes(3, "big") + b"\x00" * 3000
    data = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    feed = FeedReader([data], eof=False)
    task = asyncio.create_task(feed.run())
    with pytest.raises(ClientHelloError):
        await read_client_hello(feed.reader, max_bytes=1024)
    await task
