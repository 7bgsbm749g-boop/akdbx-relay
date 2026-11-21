"""The relay: public TLS pass-through listener and the broker control API."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from . import PROTOCOL_VERSION, __version__
from .config import Config
from .csr import CSRError, validate_csr
from .httpserver import MAX_HEAD_BYTES, Handler, HTTPError, HTTPServer, Request, Response
from .issuer import IssuanceError, IssuanceRateLimited, leaf_not_after
from .names import (
    broker_id_from_host,
    hash_secret,
    is_valid_stream_id,
    new_broker_id,
    new_secret,
    new_stream_id,
)
from .ratelimit import SlidingWindow, TokenBucket
from .store import DAY, Broker, Budget, Store
from .tlspeek import ClientHelloError, read_client_hello
from .wsconn import ServerWebSocket, WSClosed

log = logging.getLogger("akdbx_relay")

CONTROL_MAX_MESSAGE = 4096
STREAM_MAX_MESSAGE = 1 << 20
READ_CHUNK = 64 * 1024
REGISTER_MAX_BODY = 4096
CERTIFICATE_MAX_BODY = 64 * 1024
ISSUANCE_QUEUE_TIMEOUT = 20.0
_SECRET_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def rate_key(ip: str) -> str:
    """Rate-limit key: the IPv4 address, or the /64 network of an IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, 64), strict=False))
    return str(addr)


class Issuer:  # pragma: no cover - interface description
    async def issue(self, name: str, csr_pem: bytes) -> str: ...
    async def cleanup_stale_records(self) -> None: ...


@dataclass
class ControlChannel:
    broker_id: str
    ws: ServerWebSocket
    last_pong: float


@dataclass
class StreamSession:
    ws: ServerWebSocket
    done: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass
class PendingStream:
    broker_id: str
    created: float
    future: "asyncio.Future[StreamSession]"


class Relay:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        issuer: Issuer | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.issuer = issuer
        self.clock = clock
        self.budget = Budget(store, cfg.cert_budget, cfg.cert_hard_limit, cfg.certs_per_broker_week)
        self.controls: dict[str, ControlChannel] = {}
        self.pending: dict[str, PendingStream] = {}
        self.streams_per_broker: dict[str, int] = {}
        self.total_streams = 0
        self.pending_handshakes = 0
        self.conn_limiter = TokenBucket(cfg.conn_rate_per_ip, cfg.conn_burst_per_ip, clock=clock)
        self.reg_limiter = SlidingWindow(cfg.registrations_per_ip_day, DAY, clock=clock)
        self._issuing: set[str] = set()
        self._issue_sem = asyncio.Semaphore(cfg.max_concurrent_issuance)
        self._servers: list[asyncio.base_events.Server] = []
        self._tasks: set[asyncio.Task] = set()
        self.http = HTTPServer(self.route)

    # Lifecycle

    async def start(self) -> None:
        if self.issuer is not None:
            await self.issuer.cleanup_stale_records()
        control = await asyncio.start_server(
            self.http.handle, self.cfg.control_host, self.cfg.control_port, limit=MAX_HEAD_BYTES
        )
        self._servers.append(control)
        public = await asyncio.start_server(
            self.handle_public, self.cfg.public_hosts, self.cfg.public_port, backlog=1024
        )
        self._servers.append(public)
        log.info(
            "akdbx relay %s listening: public %s port %d, control %s port %d",
            __version__, ",".join(self.cfg.public_hosts), self.public_port,
            self.cfg.control_host, self.control_port,
        )

    @property
    def control_port(self) -> int:
        return self._servers[0].sockets[0].getsockname()[1]

    @property
    def public_port(self) -> int:
        return self._servers[1].sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for chan in list(self.controls.values()):
            with contextlib.suppress(Exception):
                await chan.ws.close(1001, "relay shutting down")
        for task in list(self._tasks):
            task.cancel()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 5)
        self._servers.clear()

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # Public listener (:8443)

    async def handle_public(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        reserved_for: str | None = None
        try:
            peer = writer.get_extra_info("peername")
            key = rate_key(peer[0]) if peer else ""
            if not self.conn_limiter.allow(key):
                return
            del key, peer  # client addresses are not kept beyond the rate limit
            if self.pending_handshakes >= self.cfg.max_pending_handshakes:
                return
            self.pending_handshakes += 1
            try:
                hello, sni = await read_client_hello(
                    reader, self.cfg.client_hello_max_bytes, self.cfg.client_hello_timeout
                )
            except (ClientHelloError, TimeoutError, asyncio.TimeoutError, EOFError, ConnectionError, OSError):
                return
            finally:
                self.pending_handshakes -= 1
            if sni is None:
                return
            broker_id = broker_id_from_host(sni, self.cfg.domain)
            if broker_id is None:
                return
            chan = self.controls.get(broker_id)
            if chan is None:
                return
            if self.total_streams >= self.cfg.max_streams_total:
                return
            if self.streams_per_broker.get(broker_id, 0) >= self.cfg.max_streams_per_broker:
                return
            self.total_streams += 1
            self.streams_per_broker[broker_id] = self.streams_per_broker.get(broker_id, 0) + 1
            reserved_for = broker_id
            session = await self._open_stream(chan)
            if session is None:
                return
            try:
                await self._splice(reader, writer, session.ws, hello)
            finally:
                session.done.set()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("public connection error")
        finally:
            if reserved_for is not None:
                self.total_streams -= 1
                left = self.streams_per_broker.get(reserved_for, 1) - 1
                if left > 0:
                    self.streams_per_broker[reserved_for] = left
                else:
                    self.streams_per_broker.pop(reserved_for, None)
            with contextlib.suppress(Exception):
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), 2)

    async def _open_stream(self, chan: ControlChannel) -> StreamSession | None:
        stream_id = new_stream_id()
        future: asyncio.Future[StreamSession] = asyncio.get_running_loop().create_future()
        self.pending[stream_id] = PendingStream(chan.broker_id, self.clock(), future)
        try:
            try:
                await chan.ws.send(json.dumps({"type": "open", "stream": stream_id}))
            except WSClosed:
                return None
            try:
                return await asyncio.wait_for(future, self.cfg.stream_open_timeout)
            except asyncio.TimeoutError:
                return None
        finally:
            self.pending.pop(stream_id, None)

    async def _splice(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ws: ServerWebSocket,
        hello: bytes,
    ) -> None:
        loop = asyncio.get_running_loop()
        last = [loop.time()]
        close_code = [1000]

        async def client_to_broker() -> None:
            await ws.send(hello)
            while True:
                data = await reader.read(READ_CHUNK)
                if not data:
                    return
                last[0] = loop.time()
                await ws.send(data)

        async def broker_to_client() -> None:
            while True:
                msg = await ws.recv()
                if isinstance(msg, str):
                    close_code[0] = 1003  # text frames are a protocol error on streams
                    return
                last[0] = loop.time()
                writer.write(msg)
                await writer.drain()

        async def idle() -> None:
            while True:
                remaining = last[0] + self.cfg.stream_idle_timeout - loop.time()
                if remaining <= 0:
                    return
                await asyncio.sleep(remaining)

        ws.start_keepalive(self.cfg.ws_ping_interval, self.cfg.control_pong_timeout)
        tasks = [
            asyncio.create_task(client_to_broker()),
            asyncio.create_task(broker_to_client()),
            asyncio.create_task(idle()),
        ]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            del results  # errors here only mean that one side closed
            with contextlib.suppress(Exception):
                await ws.close(close_code[0])

    # Control API routing

    def route(self, method: str, path: str) -> tuple[Handler, int] | None:
        if path == "/api/v1/health" and method in ("GET", "HEAD"):
            return self.api_health, 0
        if path == "/api/v1/register":
            return (self.api_register, REGISTER_MAX_BODY) if method == "POST" else (self._method_not_allowed, 0)
        if path == "/api/v1/certificate":
            return (self.api_certificate, CERTIFICATE_MAX_BODY) if method == "POST" else (self._method_not_allowed, 0)
        if path == "/api/v1/connect":
            return (self.api_connect, 0) if method == "GET" else (self._method_not_allowed, 0)
        if path.startswith("/api/v1/stream/"):
            return (self.api_stream, 0) if method == "GET" else (self._method_not_allowed, 0)
        return None

    async def _method_not_allowed(self, req: Request) -> Response:
        raise HTTPError(405, "method_not_allowed")

    def client_ip(self, req: Request) -> str:
        """The caller's IP: CF-Connecting-IP only when the TCP peer is the local proxy."""
        if req.peer in self.cfg.trusted_proxy_ips:
            forwarded = (req.header("cf-connecting-ip") or "").strip()
            if forwarded:
                try:
                    return str(ipaddress.ip_address(forwarded))
                except ValueError:
                    pass
        return req.peer

    def authenticate(self, req: Request) -> Broker:
        value = req.header("authorization") or ""
        scheme, _, token = value.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not (20 <= len(token) <= 128) or not set(token) <= _SECRET_CHARS:
            raise HTTPError(401, "unauthorized", "missing or invalid bearer secret")
        broker = self.store.broker_by_secret_hash(hash_secret(token))
        if broker is None:
            raise HTTPError(401, "unauthorized", "missing or invalid bearer secret")
        return broker

    def fqdn(self, broker_id: str) -> str:
        return f"{broker_id}.{self.cfg.domain}"

    async def api_health(self, req: Request) -> Response:
        paused = self.budget.registration_retry_after() is not None
        return Response(200, {
            "status": "ok",
            "protocol": PROTOCOL_VERSION,
            "version": __version__,
            "registrations": "paused" if paused else "open",
        })

    async def api_register(self, req: Request) -> Response:
        ip_key = rate_key(self.client_ip(req))
        wait = self.reg_limiter.check(ip_key)
        if wait:
            raise HTTPError(429, "rate_limited", "too many registrations from this address", int(wait) + 1)
        body = req.json()
        if body.get("protocol") != PROTOCOL_VERSION:
            raise HTTPError(400, "unsupported_protocol", f"this relay speaks protocol {PROTOCOL_VERSION}")
        client = body.get("client", "")
        if not isinstance(client, str) or len(client) > 64 or not client.isprintable():
            raise HTTPError(400, "bad_request", "client must be a short printable string")
        retry_after = self.budget.registration_retry_after()
        if retry_after is not None:
            raise HTTPError(503, "registrations_paused",
                            "the relay's weekly certificate budget is used up", retry_after)
        secret = new_secret()
        for _ in range(10):
            broker_id = new_broker_id()
            if self.store.add_broker(broker_id, hash_secret(secret), client):
                break
        else:  # pragma: no cover - 60 bits of randomness
            raise HTTPError(500, "internal_error")
        self.reg_limiter.record(ip_key)
        log.info("registered a broker (%d in total)", self.store.broker_count())
        return Response(201, {
            "protocol": PROTOCOL_VERSION,
            "name": self.fqdn(broker_id),
            "broker_id": broker_id,
            "secret": secret,
            "public_port": self.cfg.advertised_port,
        })

    async def api_certificate(self, req: Request) -> Response:
        broker = self.authenticate(req)
        name = self.fqdn(broker.id)
        body = req.json()
        try:
            csr_pem = validate_csr(body.get("csr"), name)  # type: ignore[arg-type]
        except CSRError as exc:
            raise HTTPError(400, "bad_csr", str(exc)) from None
        if self.issuer is None:
            raise HTTPError(503, "issuance_paused", "certificate issuance is not configured", 3600)
        if broker.id in self._issuing:
            raise HTTPError(429, "rate_limited", "a certificate request for this broker is running", 30)
        wait = self.budget.broker_retry_after(broker.id)
        if wait is not None:
            raise HTTPError(429, "rate_limited", "too many certificates for this broker this week", wait)
        first_time = not broker.has_certificate
        if first_time:
            wait = self.budget.first_issuance_retry_after()
            if wait is not None:
                raise HTTPError(503, "issuance_paused",
                                "the relay's weekly certificate budget is used up", wait)
        self._issuing.add(broker.id)
        try:
            try:
                await asyncio.wait_for(self._issue_sem.acquire(), ISSUANCE_QUEUE_TIMEOUT)
            except asyncio.TimeoutError:
                raise HTTPError(503, "issuance_paused", "the relay is busy issuing certificates", 60) from None
            try:
                chain = await self.issuer.issue(name, csr_pem)
            finally:
                self._issue_sem.release()
        except IssuanceRateLimited as exc:
            log.warning("ACME rate limit reached")
            raise HTTPError(503, "issuance_paused", "the certificate authority's rate limit was reached",
                            exc.retry_after) from None
        except IssuanceError as exc:
            log.warning("certificate issuance failed: %s", exc)
            raise HTTPError(502, "acme_failed", "the certificate authority did not issue a certificate") from None
        finally:
            self._issuing.discard(broker.id)
        not_after = leaf_not_after(chain)
        first = self.store.record_certificate(broker.id, not_after.timestamp())
        log.info("issued a %s certificate", "first" if first else "renewal")
        return Response(200, {
            "certificate": chain,
            "not_after": not_after.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    async def api_connect(self, req: Request) -> Response | None:
        broker = self.authenticate(req)
        if not req.is_websocket:
            raise HTTPError(400, "websocket_required", "this endpoint needs a WebSocket upgrade")
        ws = await ServerWebSocket.accept(req.reader, req.writer, req.raw_head, CONTROL_MAX_MESSAGE)
        if ws is None:
            return None
        chan = ControlChannel(broker.id, ws, self.clock())
        old = self.controls.get(broker.id)
        self.controls[broker.id] = chan
        if old is not None:
            self._spawn(old.ws.close(4000, "replaced by a new control connection"))
        log.debug("control channel up")
        pinger = asyncio.create_task(self._control_pinger(chan))
        try:
            while True:
                msg = await ws.recv()
                if isinstance(msg, bytes):
                    await ws.close(1003, "binary frames are not allowed on the control channel")
                    break
                try:
                    obj = json.loads(msg)
                except ValueError:
                    await ws.close(1007, "invalid JSON")
                    break
                kind = obj.get("type") if isinstance(obj, dict) else None
                if kind == "pong":
                    chan.last_pong = self.clock()
                elif kind == "ping":
                    chan.last_pong = self.clock()
                    await ws.send('{"type":"pong"}')
                # Unknown message types are ignored for forward compatibility.
        except WSClosed:
            pass
        finally:
            pinger.cancel()
            if self.controls.get(broker.id) is chan:
                del self.controls[broker.id]
            with contextlib.suppress(Exception):
                await ws.close()
        return None

    async def _control_pinger(self, chan: ControlChannel) -> None:
        interval = self.cfg.control_ping_interval
        timeout = self.cfg.control_pong_timeout
        next_ping = self.clock() + interval
        try:
            while chan.ws.open:
                wake = min(next_ping, chan.last_pong + timeout)
                await asyncio.sleep(max(0.0, wake - self.clock()))
                now = self.clock()
                if now >= chan.last_pong + timeout:
                    log.info("control channel did not answer pings; closing it")
                    await chan.ws.close(4001, "pong timeout")
                    return
                if now >= next_ping:
                    await chan.ws.send('{"type":"ping"}')
                    next_ping = now + interval
        except (WSClosed, asyncio.CancelledError):
            return

    async def api_stream(self, req: Request) -> Response | None:
        broker = self.authenticate(req)
        stream_id = req.path[len("/api/v1/stream/"):]
        if not is_valid_stream_id(stream_id):
            raise HTTPError(404, "unknown_stream")
        pending = self.pending.get(stream_id)
        if (
            pending is None
            or pending.broker_id != broker.id
            or pending.future.done()
            or self.clock() - pending.created > self.cfg.stream_open_timeout
        ):
            raise HTTPError(404, "unknown_stream")
        if not req.is_websocket:
            raise HTTPError(400, "websocket_required", "this endpoint needs a WebSocket upgrade")
        del self.pending[stream_id]  # single use
        ws = await ServerWebSocket.accept(req.reader, req.writer, req.raw_head, STREAM_MAX_MESSAGE)
        if ws is None:
            return None
        if pending.future.done():
            await ws.close(1011, "the client connection is gone")
            return None
        session = StreamSession(ws)
        pending.future.set_result(session)
        waiters = [asyncio.create_task(session.done.wait()), asyncio.create_task(ws.wait_closed())]
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()
        await ws.wait_closed()
        return None
