"""The relay: public TLS pass-through listener and the broker control API."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ipaddress
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable

from . import PROTOCOL_VERSION, __version__
from .config import Config
from .controltls import ControlTLS
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
from .wsconn import ServerWebSocket, WSClosed, abort_writer, close_writer

log = logging.getLogger("akdbx_relay")

CONTROL_MAX_MESSAGE = 4096
STREAM_MAX_MESSAGE = 256 * 1024
STREAM_MAX_QUEUE = 4
READ_CHUNK = 64 * 1024
REGISTER_MAX_BODY = 4096
CERTIFICATE_MAX_BODY = 64 * 1024
# A certificate order needs at least this long after the DNS wait; a request
# that cannot start its order with this much time left is refused as busy.
MIN_ORDER_SECONDS = 15.0
# TLS handshake limit for connections to the control host name.
CONTROL_TLS_HANDSHAKE_TIMEOUT = 10.0
# After the client side of a control connection ends, how long the relay's
# own TLS side may take to finish.
CONTROL_DRAIN_TIMEOUT = 5.0
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
    async def issue(self, name: str, csr_pem: bytes, deadline: float | None = None) -> str: ...
    async def cleanup_stale_records(self) -> None: ...


class KeyCounter:
    """Open-item counts per rate key, held for the life of each item."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def get(self, key: str) -> int:
        return self._counts.get(key, 0)

    def acquire(self, key: str, limit: int) -> bool:
        n = self._counts.get(key, 0)
        if n >= limit:
            return False
        self._counts[key] = n + 1
        return True

    def release(self, key: str) -> None:
        n = self._counts.get(key, 0) - 1
        if n > 0:
            self._counts[key] = n
        else:
            self._counts.pop(key, None)

    def __len__(self) -> int:
        return len(self._counts)


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
        self.control_connections = 0
        self.handshakes_by_ip = KeyCounter()
        self.streams_by_ip = KeyCounter()
        self.control_by_ip = KeyCounter()
        self.conn_limiter = TokenBucket(cfg.conn_rate_per_ip, cfg.conn_burst_per_ip, clock=clock)
        self.reg_limiter = SlidingWindow(cfg.registrations_per_ip_day, DAY, clock=clock)
        self._issuing: set[str] = set()
        self._first_time_in_flight = 0
        self._public_writers: set[asyncio.StreamWriter] = set()
        self._issue_sem = asyncio.Semaphore(cfg.max_concurrent_issuance)
        self._public_server: asyncio.base_events.Server | None = None
        self._health_server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self.http = HTTPServer(self.route)
        self.health_http = HTTPServer(self.health_route)
        self.control_tls = ControlTLS(cfg, self._issue_control_certificate if issuer is not None else None)

    # Lifecycle

    async def start(self) -> None:
        if self.issuer is not None:
            await self.issuer.cleanup_stale_records()
        self.control_tls.load()
        if self.cfg.health_host:
            self._health_server = await asyncio.start_server(
                self.health_http.handle, self.cfg.health_host, self.cfg.health_port, limit=MAX_HEAD_BYTES
            )
        self._public_server = await asyncio.start_server(
            self.handle_public, self.cfg.public_hosts, self.cfg.public_port, backlog=1024
        )
        self._spawn(self.control_tls.run())
        log.info(
            "akdbx relay %s listening: public %s port %d (control API at https://%s:%d), health %s",
            __version__, ",".join(self.cfg.public_hosts), self.public_port,
            self.cfg.control_hostname, self.cfg.advertised_port,
            f"{self.cfg.health_host} port {self.health_port}" if self._health_server else "off",
        )

    @property
    def health_port(self) -> int:
        assert self._health_server is not None
        return self._health_server.sockets[0].getsockname()[1]

    @property
    def public_port(self) -> int:
        assert self._public_server is not None
        return self._public_server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        servers = [srv for srv in (self._public_server, self._health_server) if srv is not None]
        for server in servers:
            server.close()
        await asyncio.gather(
            *(chan.ws.close(1001, "relay shutting down", timeout=2) for chan in list(self.controls.values())),
            return_exceptions=True,
        )
        for writer in list(self._public_writers):
            abort_writer(writer)
        for task in list(self._tasks):
            task.cancel()
        for server in servers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 5)
        self._public_server = self._health_server = None

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # Public listener (:8443)

    async def handle_public(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        reserved_for: str | None = None
        self._public_writers.add(writer)
        # The client address stays in this frame only: for the rate limit and
        # the per-address counts, never in logs or on disk.
        peer = writer.get_extra_info("peername")
        ip = str(peer[0]) if peer else ""
        key = rate_key(ip)
        try:
            if not self.conn_limiter.allow(key):
                return
            if self.pending_handshakes >= self.cfg.max_pending_handshakes:
                return
            if not self.handshakes_by_ip.acquire(key, self.cfg.max_handshakes_per_ip):
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
                self.handshakes_by_ip.release(key)
            if sni is None:
                return
            if sni == self.cfg.control_hostname:
                await self._serve_control(reader, writer, hello, ip, key)
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
            if not self.streams_by_ip.acquire(key, self.cfg.max_streams_per_ip):
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
            self._public_writers.discard(writer)
            if reserved_for is not None:
                self.streams_by_ip.release(key)
                self.total_streams -= 1
                left = self.streams_per_broker.get(reserved_for, 1) - 1
                if left > 0:
                    self.streams_per_broker[reserved_for] = left
                else:
                    self.streams_per_broker.pop(reserved_for, None)
            await close_writer(writer)

    # Control API over TLS on the public port

    async def _serve_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             hello: bytes, ip: str, key: str) -> None:
        """Terminate TLS for the control host name inside the relay.

        The ClientHello is already read from the socket, so the relay feeds
        the connection through a local socket pair into asyncio's TLS server
        side: client bytes (starting with the buffered ClientHello) go in one
        end, the TLS server reads the other. No third party sees the
        decrypted requests or the brokers' bearer secrets.
        """
        ctx = self.control_tls.context
        if ctx is None:
            return
        if self.control_connections >= self.cfg.max_control_connections:
            return
        if not self.control_by_ip.acquire(key, self.cfg.max_control_connections_per_ip):
            return
        self.control_connections += 1
        outer, inner = socket.socketpair()
        bridge_writer: asyncio.StreamWriter | None = None
        try:
            outer.setblocking(False)
            inner.setblocking(False)
            bridge_reader, bridge_writer = await asyncio.open_connection(sock=outer)
            self._public_writers.add(bridge_writer)
            self._spawn(self._control_session(inner, ctx, ip))
            inner = None  # owned by the session task now
            bridge_writer.write(hello)

            async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                # Read until EOF even after the other side stops taking data,
                # so the socket is never closed with unread bytes (which
                # would reset the connection and lose the last frames).
                forward = True
                with contextlib.suppress(ConnectionError, OSError):
                    while True:
                        data = await src.read(READ_CHUNK)
                        if not data:
                            break
                        if forward:
                            try:
                                dst.write(data)
                                await dst.drain()
                            except (ConnectionError, OSError, RuntimeError):
                                forward = False
                if forward and dst.can_write_eof():
                    with contextlib.suppress(ConnectionError, OSError, RuntimeError):
                        dst.write_eof()

            pumps = {asyncio.create_task(pump(reader, bridge_writer)),
                     asyncio.create_task(pump(bridge_reader, writer))}
            try:
                _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
                if pending:
                    # One side finished; give the other a moment to finish too.
                    await asyncio.wait(pending, timeout=CONTROL_DRAIN_TIMEOUT)
            finally:
                for task in pumps:
                    task.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
        finally:
            if inner is not None:
                inner.close()
            if bridge_writer is not None:
                self._public_writers.discard(bridge_writer)
                await close_writer(bridge_writer)
            else:
                outer.close()
            self.control_connections -= 1
            self.control_by_ip.release(key)

    async def _control_session(self, sock: socket.socket, ctx: "ssl.SSLContext", ip: str) -> None:
        """Serve the control API on the relay's end of a socket pair, over TLS."""
        loop = asyncio.get_running_loop()
        done = loop.create_future()

        def connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            async def run() -> None:
                try:
                    await self.http.handle(reader, writer, peer=ip)
                finally:
                    if not done.done():
                        done.set_result(None)
            return run()

        def factory() -> asyncio.StreamReaderProtocol:
            return asyncio.StreamReaderProtocol(asyncio.StreamReader(limit=MAX_HEAD_BYTES), connected)

        try:
            transport, _ = await loop.connect_accepted_socket(
                factory, sock, ssl=ctx, ssl_handshake_timeout=CONTROL_TLS_HANDSHAKE_TIMEOUT
            )
        except Exception:  # handshake failure or timeout: nothing to answer
            sock.close()
            return
        try:
            await done
        finally:
            if not transport.is_closing():
                transport.abort()

    async def _open_stream(self, chan: ControlChannel) -> StreamSession | None:
        """Announce a stream and wait for the broker to open it.

        One deadline covers both the `open` message on the control channel
        (whose send blocks if the broker stops reading) and the broker's
        stream WebSocket.
        """
        stream_id = new_stream_id()
        future: asyncio.Future[StreamSession] = asyncio.get_running_loop().create_future()
        self.pending[stream_id] = PendingStream(chan.broker_id, self.clock(), future)
        try:
            async with asyncio.timeout(self.cfg.stream_open_timeout):
                await chan.ws.send(json.dumps({"type": "open", "stream": stream_id}))
                return await future
        except (WSClosed, TimeoutError, asyncio.TimeoutError):
            return None
        finally:
            self.pending.pop(stream_id, None)
            if not future.done():
                future.cancel()

    async def _splice(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ws: ServerWebSocket,
        hello: bytes,
    ) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        last = [started]
        broker_spoke = [False]
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
                broker_spoke[0] = True
                writer.write(msg)
                await writer.drain()

        async def idle() -> None:
            # A shorter limit holds until the broker's first bytes (its TLS
            # ServerHello), so a broker that accepts streams but never
            # answers cannot keep stream slots for the whole idle timeout.
            while True:
                if broker_spoke[0]:
                    remaining = last[0] + self.cfg.stream_idle_timeout - loop.time()
                else:
                    first = min(self.cfg.stream_first_byte_timeout, self.cfg.stream_idle_timeout)
                    remaining = started + first - loop.time()
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

    def health_route(self, method: str, path: str) -> tuple[Handler, int] | None:
        """The loopback plain-HTTP port answers only the health check."""
        if path == "/api/v1/health" and method in ("GET", "HEAD"):
            return self.api_health, 0
        return None

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
        # The TCP peer of the public connection. No proxy is in the path, so
        # no forwarded-address header is trusted.
        ip_key = rate_key(req.peer)
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
            wait = self.budget.first_issuance_retry_after(self._first_time_in_flight)
            if wait is not None:
                raise HTTPError(503, "issuance_paused",
                                "the relay's weekly certificate budget is used up", wait)
        self._issuing.add(broker.id)
        if first_time:
            self._first_time_in_flight += 1
        try:
            chain = await self._issue(name, csr_pem)
        finally:
            self._issuing.discard(broker.id)
            if first_time:
                self._first_time_in_flight -= 1
        not_after = leaf_not_after(chain)
        first = self.store.record_certificate(broker.id, not_after.timestamp())
        log.info("issued a %s certificate", "first" if first else "renewal")
        return Response(200, {
            "certificate": chain,
            "not_after": not_after.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    async def _issue(self, name: str, csr_pem: bytes) -> str:
        """Queue for an issuance slot and run the order, all within one deadline.

        The deadline (AKDBX_RELAY_CERTIFICATE_DEADLINE) starts when the
        request is accepted and covers the wait for a slot and the ACME order.
        A request that cannot start its order with MIN_ORDER_SECONDS plus the
        DNS wait left (at most half the deadline) gets 503 instead of starting
        an order that could not finish in time.
        """
        assert self.issuer is not None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.cfg.certificate_deadline
        busy = HTTPError(503, "issuance_paused", "the relay is busy issuing certificates", 60)
        min_order = min(self.cfg.dns_propagation_seconds + MIN_ORDER_SECONDS, self.cfg.certificate_deadline / 2)
        latest_start = deadline - min_order
        try:
            async with asyncio.timeout_at(deadline):
                if latest_start <= loop.time():
                    raise busy
                try:
                    await asyncio.wait_for(self._issue_sem.acquire(), latest_start - loop.time())
                except (TimeoutError, asyncio.TimeoutError):
                    raise busy from None
                try:
                    return await self.issuer.issue(name, csr_pem, deadline=deadline)
                finally:
                    self._issue_sem.release()
        except (TimeoutError, asyncio.TimeoutError):
            log.warning("certificate request deadline passed")
            raise HTTPError(502, "acme_failed", "the certificate request took too long") from None
        except IssuanceRateLimited as exc:
            log.warning("ACME rate limit reached")
            raise HTTPError(503, "issuance_paused", "the certificate authority's rate limit was reached",
                            exc.retry_after) from None
        except IssuanceError as exc:
            log.warning("certificate issuance failed: %s", exc)
            raise HTTPError(502, "acme_failed", "the certificate authority did not issue a certificate") from None

    async def _issue_control_certificate(self, name: str, csr_pem: bytes) -> str:
        """The relay's own control certificate, through the same queue and deadline."""
        try:
            return await self._issue(name, csr_pem)
        except HTTPError as exc:
            raise IssuanceError(f"control certificate: {exc.code}") from None

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
                    try:
                        # A broker that stops reading must not stall the pong check.
                        async with asyncio.timeout(max(0.1, chan.last_pong + timeout - now)):
                            await chan.ws.send('{"type":"ping"}')
                    except (TimeoutError, asyncio.TimeoutError):
                        log.info("control channel is not reading; closing it")
                        await chan.ws.close(4001, "pong timeout")
                        return
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
        ws = await ServerWebSocket.accept(req.reader, req.writer, req.raw_head, STREAM_MAX_MESSAGE,
                                          STREAM_MAX_QUEUE)
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
