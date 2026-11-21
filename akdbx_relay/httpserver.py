"""A small HTTP/1.1 server for the control API (one request per connection).

It runs on 127.0.0.1 behind Caddy. It parses only what the API needs and
enforces size and time limits on the request head and body.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

log = logging.getLogger("akdbx_relay.http")

MAX_HEAD_BYTES = 16 * 1024
MAX_HEADERS = 100
HEAD_TIMEOUT = 10.0
BODY_TIMEOUT = 30.0

_REASONS = {
    200: "OK",
    201: "Created",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    411: "Length Required",
    413: "Content Too Large",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


class HTTPError(Exception):
    def __init__(self, status: int, code: str, message: str = "", retry_after: int | None = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message or code.replace("_", " ")
        self.retry_after = retry_after

    def response(self) -> "Response":
        body: dict[str, object] = {"error": self.code, "message": self.message}
        headers: list[tuple[str, str]] = []
        if self.retry_after is not None:
            body["retry_after"] = self.retry_after
            headers.append(("Retry-After", str(self.retry_after)))
        return Response(self.status, body, headers)


@dataclass
class Response:
    status: int
    body: object
    headers: list[tuple[str, str]] = field(default_factory=list)

    def serialize(self, head_only: bool = False) -> bytes:
        payload = json.dumps(self.body, separators=(",", ":")).encode("utf-8")
        lines = [
            f"HTTP/1.1 {self.status} {_REASONS.get(self.status, 'Status')}",
            "Content-Type: application/json",
            f"Content-Length: {len(payload)}",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
            "Connection: close",
        ]
        lines += [f"{k}: {v}" for k, v in self.headers]
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        return head if head_only else head + payload


@dataclass
class Request:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    raw_head: bytes
    peer: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    body: bytes = b""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def is_websocket(self) -> bool:
        return (self.header("upgrade") or "").lower() == "websocket"

    def json(self) -> dict:
        try:
            value = json.loads(self.body.decode("utf-8")) if self.body else {}
        except (UnicodeDecodeError, ValueError) as exc:
            raise HTTPError(400, "bad_request", "body must be JSON") from exc
        if not isinstance(value, dict):
            raise HTTPError(400, "bad_request", "body must be a JSON object")
        return value


# A handler returns a Response, or None when it took over the connection
# (WebSocket upgrades).
Handler = Callable[[Request], Awaitable["Response | None"]]


def _parse_head(raw: bytes) -> tuple[str, str, str, dict[str, str]]:
    try:
        text = raw.decode("latin-1")
    except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 decodes everything
        raise HTTPError(400, "bad_request") from exc
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise HTTPError(400, "bad_request", "bad request line")
    method, target, _version = parts
    if not target.startswith("/"):
        raise HTTPError(400, "bad_request", "bad request target")
    path, _, query = target.partition("?")
    headers: dict[str, str] = {}
    count = 0
    for line in lines[1:]:
        if not line:
            continue
        count += 1
        if count > MAX_HEADERS:
            raise HTTPError(431, "headers_too_large")
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip() or any(c in name for c in " \t"):
            raise HTTPError(400, "bad_request", "bad header")
        key = name.lower()
        value = value.strip()
        if key in headers:
            if key in ("content-length", "authorization", "host", "transfer-encoding", "cf-connecting-ip"):
                raise HTTPError(400, "bad_request", "duplicate header")
            headers[key] = headers[key] + ", " + value
        else:
            headers[key] = value
    return method, path, query, headers


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str], max_body: int) -> bytes:
    te = headers.get("transfer-encoding", "").lower()
    if te:
        if te != "chunked":
            raise HTTPError(400, "bad_request", "unsupported transfer encoding")
        if "content-length" in headers:
            raise HTTPError(400, "bad_request", "both content-length and chunked")
        out = bytearray()
        while True:
            line = await reader.readuntil(b"\r\n")
            size_text = line[:-2].split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError as exc:
                raise HTTPError(400, "bad_request", "bad chunk size") from exc
            if size < 0 or len(out) + size > max_body:
                raise HTTPError(413, "body_too_large")
            if size == 0:
                # Trailers, up to the blank line.
                while (await reader.readuntil(b"\r\n")) != b"\r\n":
                    pass
                return bytes(out)
            out += await reader.readexactly(size)
            if await reader.readexactly(2) != b"\r\n":
                raise HTTPError(400, "bad_request", "bad chunk")
    length_text = headers.get("content-length")
    if length_text is None:
        return b""
    if not length_text.isdigit():
        raise HTTPError(400, "bad_request", "bad content-length")
    length = int(length_text)
    if length > max_body:
        raise HTTPError(413, "body_too_large")
    return await reader.readexactly(length) if length else b""


class HTTPServer:
    """Routes: list of (method, path or prefix ending in '/', max body, handler)."""

    def __init__(self, router: Callable[[str, str], tuple[Handler, int] | None]) -> None:
        self.router = router

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        peer = peername[0] if peername else ""
        took_over = False
        try:
            try:
                raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            except (asyncio.IncompleteReadError, ConnectionError):
                return
            except asyncio.LimitOverrunError:
                await self._send(writer, HTTPError(431, "headers_too_large").response())
                return
            except asyncio.TimeoutError:
                await self._send(writer, HTTPError(408, "timeout").response())
                return
            except ValueError:
                await self._send(writer, HTTPError(431, "headers_too_large").response())
                return
            try:
                method, path, query, headers = _parse_head(raw_head)
                route = self.router(method, path)
                if route is None:
                    raise HTTPError(404, "not_found")
                handler, max_body = route
                body = b""
                if method == "POST":
                    body = await asyncio.wait_for(_read_body(reader, headers, max_body), BODY_TIMEOUT)
                request = Request(method, path, query, headers, raw_head, peer, reader, writer, body)
                response = await handler(request)
                if response is None:
                    took_over = True
                    return
            except HTTPError as exc:
                response = exc.response()
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
                response = HTTPError(400, "bad_request").response()
            except asyncio.TimeoutError:
                response = HTTPError(408, "timeout").response()
            except Exception:
                log.exception("unhandled error in control API")
                response = HTTPError(500, "internal_error").response()
            await self._send(writer, response, head_only=False)
        finally:
            if not took_over:
                with contextlib.suppress(Exception):
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), 2)

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, response: Response, head_only: bool = False) -> None:
        with contextlib.suppress(ConnectionError, OSError, RuntimeError):
            writer.write(response.serialize(head_only))
            await writer.drain()
