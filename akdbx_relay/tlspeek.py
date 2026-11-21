"""Read a TLS ClientHello without terminating TLS, and extract the SNI name.

The relay never decrypts traffic. It only buffers the first bytes a client
sends (the ClientHello, which is plain text in TLS 1.2 and 1.3), reads the
server_name extension to choose the broker, and later replays the same bytes
to the broker unchanged.
"""

from __future__ import annotations

import asyncio
import re

MAX_CLIENT_HELLO_BYTES = 16 * 1024
CLIENT_HELLO_TIMEOUT = 5.0

_CONTENT_HANDSHAKE = 22
_HANDSHAKE_CLIENT_HELLO = 1
_EXT_SERVER_NAME = 0
_NAME_TYPE_HOST = 0
_MAX_RECORD = 2**14
# Most TLS records one ClientHello may span.
MAX_RECORDS = 8
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ClientHelloError(Exception):
    """The bytes are not a well-formed TLS ClientHello."""


class NeedMoreData(Exception):
    """The ClientHello is not complete yet."""


class _Cursor:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None) -> None:
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise ClientHelloError("truncated field")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def sub(self, n: int) -> "_Cursor":
        if n < 0 or self.pos + n > self.end:
            raise ClientHelloError("truncated vector")
        cur = _Cursor(self.data, self.pos, self.pos + n)
        self.pos += n
        return cur

    @property
    def remaining(self) -> int:
        return self.end - self.pos


class ClientHelloParser:
    """Incremental ClientHello reader: each byte is examined once.

    feed() takes the next bytes from the connection. It returns True when
    the full ClientHello is buffered (then `sni` holds the result), False
    when more bytes are needed, and raises ClientHelloError for malformed or
    oversized input. Record headers and payloads are consumed as they
    arrive, so many small records cost linear time, and more than
    MAX_RECORDS records are refused (real clients use one or two).
    """

    def __init__(self, max_bytes: int = MAX_CLIENT_HELLO_BYTES) -> None:
        self.max_bytes = max_bytes
        self.records = 0
        self.total = 0  # bytes fed so far
        self.done = False
        self.sni: str | None = None
        self._pending = bytearray()  # bytes of the current record not yet consumed
        self._record_left = 0  # payload bytes still due for the current record
        self._payload = bytearray()  # joined handshake payload
        self._needed: int | None = None  # full handshake message length, once known

    def feed(self, data: bytes) -> bool:
        if self.done:
            return True
        self.total += len(data)
        self._pending += data
        while True:
            if self._record_left == 0:
                if len(self._pending) < 5:
                    break
                header = bytes(self._pending[:5])
                del self._pending[:5]
                if header[0] != _CONTENT_HANDSHAKE:
                    raise ClientHelloError("not a TLS handshake record")
                if header[1] != 3:
                    raise ClientHelloError("unsupported record version")
                length = int.from_bytes(header[3:5], "big")
                if length == 0 or length > _MAX_RECORD:
                    raise ClientHelloError("bad record length")
                self.records += 1
                if self.records > MAX_RECORDS:
                    raise ClientHelloError("ClientHello split into too many records")
                consumed = self.total - len(self._pending)
                if consumed + length > self.max_bytes:
                    raise ClientHelloError("ClientHello too large")
                self._record_left = length
            take = min(self._record_left, len(self._pending))
            if take == 0:
                break
            self._payload += self._pending[:take]
            del self._pending[:take]
            self._record_left -= take
            if self._needed is None and len(self._payload) >= 4:
                if self._payload[0] != _HANDSHAKE_CLIENT_HELLO:
                    raise ClientHelloError("first handshake message is not ClientHello")
                self._needed = 4 + int.from_bytes(self._payload[1:4], "big")
                if self._needed > self.max_bytes:
                    raise ClientHelloError("ClientHello too large")
            if self._needed is not None and len(self._payload) >= self._needed:
                self.sni = _parse_message(bytes(self._payload[: self._needed]))
                self.done = True
                self._pending.clear()
                return True
        if self.total >= self.max_bytes:
            raise ClientHelloError("ClientHello too large")
        return False


def _valid_hostname(raw: bytes) -> str:
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClientHelloError("non-ASCII server name") from exc
    name = name.lower()
    if name.endswith("."):
        name = name[:-1]
    if not 1 <= len(name) <= 253:
        raise ClientHelloError("bad server name length")
    for label in name.split("."):
        if not _LABEL.match(label):
            raise ClientHelloError("bad server name label")
    return name


def parse_client_hello(buf: bytes, max_bytes: int = MAX_CLIENT_HELLO_BYTES) -> str | None:
    """Return the SNI host name (lower case) of the ClientHello at the start of buf.

    Returns None when the ClientHello is complete but carries no SNI.
    Raises NeedMoreData when more bytes are needed and ClientHelloError for
    malformed input.
    """
    if buf and buf[0] != _CONTENT_HANDSHAKE:
        raise ClientHelloError("not a TLS handshake record")
    parser = ClientHelloParser(max_bytes)
    if not parser.feed(buf):
        raise NeedMoreData
    return parser.sni


def _parse_message(msg: bytes) -> str | None:
    """Parse one complete ClientHello handshake message; return the SNI name."""
    cur = _Cursor(msg)
    cur.u8()  # handshake type, checked above
    body = cur.sub(cur.u24())
    legacy_version = body.u16()
    if legacy_version >> 8 != 3:
        raise ClientHelloError("unsupported ClientHello version")
    body.take(32)  # random
    session_id_len = body.u8()
    if session_id_len > 32:
        raise ClientHelloError("bad session id")
    body.take(session_id_len)
    suites_len = body.u16()
    if suites_len < 2 or suites_len % 2:
        raise ClientHelloError("bad cipher suites")
    body.take(suites_len)
    comp_len = body.u8()
    if comp_len < 1:
        raise ClientHelloError("bad compression methods")
    body.take(comp_len)
    if body.remaining == 0:
        return None
    exts = body.sub(body.u16())
    if body.remaining != 0:
        raise ClientHelloError("trailing bytes after extensions")
    seen: set[int] = set()
    sni: str | None = None
    while exts.remaining:
        ext_type = exts.u16()
        ext = exts.sub(exts.u16())
        if ext_type in seen:
            raise ClientHelloError("duplicate extension")
        seen.add(ext_type)
        if ext_type != _EXT_SERVER_NAME:
            continue
        names = ext.sub(ext.u16())
        if ext.remaining:
            raise ClientHelloError("trailing bytes in server_name")
        if names.remaining == 0:
            raise ClientHelloError("empty server_name list")
        while names.remaining:
            name_type = names.u8()
            raw = names.take(names.u16())
            if name_type != _NAME_TYPE_HOST:
                continue
            if sni is not None:
                raise ClientHelloError("more than one host name")
            sni = _valid_hostname(raw)
    return sni


async def read_client_hello(
    reader: asyncio.StreamReader,
    max_bytes: int = MAX_CLIENT_HELLO_BYTES,
    timeout: float = CLIENT_HELLO_TIMEOUT,
) -> tuple[bytes, str | None]:
    """Read bytes until a full ClientHello is buffered.

    Returns (buffered bytes, SNI name or None). The buffered bytes must be
    replayed to the broker unchanged. Raises ClientHelloError, TimeoutError
    or EOFError.
    """
    buf = bytearray()
    parser = ClientHelloParser(max_bytes)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError("ClientHello timeout")
        chunk = await asyncio.wait_for(reader.read(max_bytes - len(buf)), remaining)
        if not chunk:
            raise EOFError("connection closed before ClientHello")
        buf += chunk
        if parser.feed(chunk):
            return bytes(buf), parser.sni
