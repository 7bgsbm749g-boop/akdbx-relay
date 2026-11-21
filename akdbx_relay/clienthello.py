"""Read the SNI host name from a TLS ClientHello without terminating TLS.

The relay never decrypts anything. It only needs the ``server_name``
extension of the first handshake message, which TLS sends in the clear.
The parser is strict and bounds-checked: any malformed input raises
:class:`ClientHelloError`, and incomplete input returns ``None`` so the caller
can read more bytes (up to its own size and time limits).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

CONTENT_TYPE_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO = 1
EXT_SERVER_NAME = 0
NAME_TYPE_HOST_NAME = 0
MAX_RECORD_LENGTH = 16384  # TLSPlaintext.length must not exceed 2^14
DEFAULT_MAX_BYTES = 16384
MAX_HOSTNAME_LENGTH = 253

_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


class ClientHelloError(ValueError):
    """The bytes are not a well-formed TLS ClientHello."""


@dataclass(frozen=True)
class ClientHello:
    server_name: str | None
    """Lower-case SNI host name, or None when the client sent no SNI."""
    record_bytes: int
    """Number of bytes (records) that carried the ClientHello."""


class _Reader:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes | memoryview, start: int = 0, end: int | None = None):
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end

    def remaining(self) -> int:
        return self.end - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise ClientHelloError("truncated ClientHello field")
        out = bytes(self.data[self.pos : self.pos + n])
        self.pos += n
        return out

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, len_size: int, minimum: int = 0, maximum: int | None = None) -> "_Reader":
        length = self.uint(len_size)
        if length < minimum or (maximum is not None and length > maximum):
            raise ClientHelloError("vector length out of range")
        if self.pos + length > self.end:
            raise ClientHelloError("vector exceeds its container")
        sub = _Reader(self.data, self.pos, self.pos + length)
        self.pos += length
        return sub


def _normalize_host_name(raw: bytes) -> str:
    if not raw or len(raw) > MAX_HOSTNAME_LENGTH + 1:
        raise ClientHelloError("bad host name length")
    try:
        name = raw.decode("ascii").lower()
    except UnicodeDecodeError:
        raise ClientHelloError("host name is not ASCII") from None
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > MAX_HOSTNAME_LENGTH:
        raise ClientHelloError("bad host name length")
    for label in name.split("."):
        if not label or len(label) > 63:
            raise ClientHelloError("bad host name label")
        if not set(label) <= _HOST_CHARS:
            raise ClientHelloError("bad host name character")
    return name


def _parse_server_name(ext: _Reader) -> str | None:
    names = ext.vector(2, minimum=1)
    if ext.remaining():
        raise ClientHelloError("trailing bytes in server_name extension")
    host: str | None = None
    while names.remaining():
        name_type = names.uint(1)
        value = names.vector(2, minimum=1)
        raw = value.take(value.remaining())
        if name_type == NAME_TYPE_HOST_NAME:
            if host is not None:
                raise ClientHelloError("more than one host_name")
            host = _normalize_host_name(raw)
    return host


def _parse_body(body: bytes) -> str | None:
    r = _Reader(body)
    version = r.uint(2)
    if version >> 8 != 3:
        raise ClientHelloError("unsupported legacy_version")
    r.take(32)  # random
    r.vector(1, maximum=32)  # legacy_session_id
    suites = r.vector(2, minimum=2)
    if suites.remaining() % 2:
        raise ClientHelloError("odd cipher_suites length")
    r.vector(1, minimum=1)  # legacy_compression_methods
    if not r.remaining():
        return None  # no extensions at all
    exts = r.vector(2)
    if r.remaining():
        raise ClientHelloError("trailing bytes after extensions")
    seen: set[int] = set()
    server_name: str | None = None
    while exts.remaining():
        ext_type = exts.uint(2)
        ext = exts.vector(2)
        if ext_type in seen:
            raise ClientHelloError("duplicate extension")
        seen.add(ext_type)
        if ext_type == EXT_SERVER_NAME:
            server_name = _parse_server_name(ext)
    return server_name


def parse_client_hello(buf: bytes | bytearray | memoryview, max_bytes: int = DEFAULT_MAX_BYTES) -> ClientHello | None:
    """Parse the ClientHello at the start of ``buf``.

    Returns ``None`` when more bytes are needed. Raises
    :class:`ClientHelloError` for anything that is not a ClientHello or that
    would need more than ``max_bytes`` bytes.
    """
    data = memoryview(bytes(buf))
    pos = 0
    handshake = bytearray()
    while True:
        if pos >= max_bytes:
            raise ClientHelloError("ClientHello too large")
        if len(data) - pos < 5:
            return None
        content_type = data[pos]
        if content_type != CONTENT_TYPE_HANDSHAKE:
            raise ClientHelloError("not a TLS handshake record")
        if data[pos + 1] != 3:
            raise ClientHelloError("unsupported record version")
        length = int.from_bytes(data[pos + 3 : pos + 5], "big")
        if length == 0 or length > MAX_RECORD_LENGTH:
            raise ClientHelloError("bad record length")
        if pos + 5 + length > max_bytes:
            raise ClientHelloError("ClientHello too large")
        if len(data) - pos - 5 < length:
            return None
        handshake += data[pos + 5 : pos + 5 + length]
        pos += 5 + length
        if len(handshake) >= 4:
            if handshake[0] != HANDSHAKE_CLIENT_HELLO:
                raise ClientHelloError("first handshake message is not ClientHello")
            message_length = int.from_bytes(handshake[1:4], "big")
            if message_length + 4 > max_bytes:
                raise ClientHelloError("ClientHello too large")
            if len(handshake) >= 4 + message_length:
                body = bytes(handshake[4 : 4 + message_length])
                return ClientHello(server_name=_parse_body(body), record_bytes=pos)


async def read_client_hello(
    reader: asyncio.StreamReader, max_bytes: int = DEFAULT_MAX_BYTES
) -> tuple[bytes, ClientHello]:
    """Read from ``reader`` until a full ClientHello is buffered.

    Returns every byte read (to be replayed unchanged) and the parse result.
    The caller applies the time limit.
    """
    buf = bytearray()
    while True:
        chunk = await reader.read(max(1, max_bytes - len(buf)))
        if not chunk:
            raise ClientHelloError("connection closed before ClientHello")
        buf += chunk
        hello = parse_client_hello(buf, max_bytes)
        if hello is not None:
            return bytes(buf), hello
        if len(buf) >= max_bytes:
            raise ClientHelloError("ClientHello too large")
