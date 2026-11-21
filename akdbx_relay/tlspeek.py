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


def _handshake_bytes(buf: bytes, max_bytes: int) -> bytes:
    """Join handshake-record payloads until one full handshake message exists."""
    payload = bytearray()
    pos = 0
    needed: int | None = None
    while True:
        if needed is not None and len(payload) >= needed:
            return bytes(payload[:needed])
        if len(buf) - pos < 5:
            if len(buf) >= max_bytes:
                raise ClientHelloError("ClientHello too large")
            raise NeedMoreData
        ctype = buf[pos]
        major = buf[pos + 1]
        length = int.from_bytes(buf[pos + 3 : pos + 5], "big")
        if ctype != _CONTENT_HANDSHAKE:
            raise ClientHelloError("not a TLS handshake record")
        if major != 3:
            raise ClientHelloError("unsupported record version")
        if length == 0 or length > _MAX_RECORD:
            raise ClientHelloError("bad record length")
        if len(buf) - pos - 5 < length:
            if pos + 5 + length > max_bytes:
                raise ClientHelloError("ClientHello too large")
            raise NeedMoreData
        payload += buf[pos + 5 : pos + 5 + length]
        pos += 5 + length
        if needed is None and len(payload) >= 4:
            if payload[0] != _HANDSHAKE_CLIENT_HELLO:
                raise ClientHelloError("first handshake message is not ClientHello")
            needed = 4 + int.from_bytes(payload[1:4], "big")
            if needed > max_bytes:
                raise ClientHelloError("ClientHello too large")


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
    msg = _handshake_bytes(buf, max_bytes)
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
    buf = b""
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
        try:
            return buf, parse_client_hello(buf, max_bytes)
        except NeedMoreData:
            if len(buf) >= max_bytes:
                raise ClientHelloError("ClientHello too large") from None
