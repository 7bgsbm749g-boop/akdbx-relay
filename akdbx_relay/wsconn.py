"""Server-side WebSocket connections on top of the websockets sans-I/O protocol.

The control API needs plain HTTP POST endpoints and WebSocket endpoints on one
port. The websockets asyncio server handles only GET, so this module drives
the library's tested sans-I/O ``ServerProtocol`` with asyncio streams.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import logging

from websockets.frames import Opcode
from websockets.http11 import Request as WSRequest
from websockets.protocol import State
from websockets.server import ServerProtocol

log = logging.getLogger("akdbx_relay.ws")

# websockets logs handshake headers at DEBUG. Those include the bearer
# secret, so keep its loggers quiet whatever the relay's own level is.
for _name in ("websockets", "websockets.server", "websockets.client", "websockets.protocol"):
    logging.getLogger(_name).setLevel(logging.WARNING)

# Most fragments one message may have. Real clients send one frame per
# message; a cap keeps empty fragments from growing state without limit.
MAX_FRAGMENTS = 256
# One deadline for a whole close: closing frame, closing handshake, and the
# transport flush. When it passes, the transport is aborted.
CLOSE_TIMEOUT = 5.0


def abort_writer(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.transport.abort()


async def close_writer(writer: asyncio.StreamWriter, timeout: float = 2.0) -> None:
    """Close a stream writer; abort it if its buffer does not flush in time."""
    with contextlib.suppress(Exception):
        writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout)
    except (asyncio.TimeoutError, TimeoutError):
        abort_writer(writer)
    except Exception:
        pass


class WSClosed(Exception):
    def __init__(self, code: int | None = None, reason: str = "") -> None:
        super().__init__(f"websocket closed ({code})")
        self.code = code
        self.reason = reason


class ServerWebSocket:
    """One accepted WebSocket. Use recv(), send(), close()."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: ServerProtocol,
        max_queue: int = 16,
        max_size: int | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.protocol = protocol
        self.max_queue = max_queue
        self._messages: collections.deque[str | bytes] = collections.deque()
        self._data_ready = asyncio.Event()
        self._space = asyncio.Event()
        self._space.set()
        self._done = asyncio.Event()
        self._activity = asyncio.Event()  # set on every received chunk
        self._reading_paused = False
        self._failed = False
        self.max_size = max_size
        self._fragments = bytearray()
        self._fragment_count = 0
        self._fragment_opcode: Opcode | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None

    @classmethod
    async def accept(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        raw_head: bytes,
        max_size: int,
        max_queue: int = 16,
    ) -> "ServerWebSocket | None":
        """Complete the opening handshake for an already-read request head.

        Returns None (after sending an error response) if the request is not
        a valid WebSocket handshake.
        """
        protocol = ServerProtocol(max_size=max_size)
        protocol.receive_data(raw_head)
        events = protocol.events_received()
        request = events[0] if events else None
        if not isinstance(request, WSRequest):
            response = protocol.reject(400, "Bad WebSocket handshake.\n")
        else:
            response = protocol.accept(request)
        with contextlib.suppress(KeyError):
            del response.headers["Server"]
        protocol.send_response(response)
        ws = cls(reader, writer, protocol, max_queue, max_size)
        await ws._flush()
        if response.status_code != 101:
            await ws._close_transport()
            return None
        ws._reader_task = asyncio.create_task(ws._read_loop())
        return ws

    @property
    def open(self) -> bool:
        return self.protocol.state is State.OPEN and not self._done.is_set()

    @property
    def close_code(self) -> int | None:
        return self.protocol.close_code

    async def _flush(self) -> None:
        for data in self.protocol.data_to_send():
            if data:
                self.writer.write(data)
            elif self.writer.can_write_eof():
                with contextlib.suppress(OSError, RuntimeError):
                    self.writer.write_eof()
        with contextlib.suppress(ConnectionError, OSError, RuntimeError):
            await self.writer.drain()

    def _deliver(self, opcode: Opcode, payload: bytes) -> None:
        if opcode is Opcode.TEXT:
            try:
                msg: str | bytes = payload.decode("utf-8")
            except UnicodeDecodeError:
                self._fail(1007, "invalid UTF-8")
                return
        else:
            msg = payload
        self._messages.append(msg)
        self._data_ready.set()

    def _add_fragment(self, data: bytes) -> bool:
        """Append one fragment. Returns False (and fails the connection) past a limit."""
        self._fragment_count += 1
        if self._fragment_count > MAX_FRAGMENTS:
            self._fail(1009, "too many fragments")
            return False
        if self.max_size is not None and len(self._fragments) + len(data) > self.max_size:
            self._fail(1009, "message too big")
            return False
        self._fragments += data
        return True

    def _fail(self, code: int, reason: str) -> None:
        self._failed = True
        self._fragments = bytearray()
        self._fragment_count = 0
        self._fragment_opcode = None
        if self.protocol.state is State.OPEN:
            self.protocol.fail(code, reason)

    def _handle_events(self) -> None:
        for event in self.protocol.events_received():
            if self._failed:
                break  # the connection is failing; later frames are dropped
            opcode = event.opcode
            if opcode in (Opcode.TEXT, Opcode.BINARY):
                if event.fin:
                    self._deliver(opcode, bytes(event.data))
                else:
                    self._fragments = bytearray()
                    self._fragment_count = 0
                    self._fragment_opcode = opcode
                    self._add_fragment(event.data)
            elif opcode is Opcode.CONT:
                if self._fragment_opcode is None or not self._add_fragment(event.data):
                    continue
                if event.fin:
                    payload = bytes(self._fragments)
                    opcode = self._fragment_opcode
                    self._fragments = bytearray()
                    self._fragment_count = 0
                    self._fragment_opcode = None
                    self._deliver(opcode, payload)

    async def _read_loop(self) -> None:
        try:
            while True:
                try:
                    data = await self.reader.read(65536)
                except (ConnectionError, OSError):
                    data = b""
                if data:
                    self._activity.set()
                    self.protocol.receive_data(data)
                else:
                    self.protocol.receive_eof()
                self._handle_events()
                await self._flush()
                if not data or self.protocol.close_expected() or self.protocol.state is State.CLOSED:
                    break
                while len(self._messages) >= self.max_queue and not self._done.is_set():
                    self._space.clear()
                    self._reading_paused = True
                    try:
                        await self._space.wait()
                    finally:
                        self._reading_paused = False
        except asyncio.CancelledError:
            pass
        finally:
            await self._close_transport()

    async def _close_transport(self) -> None:
        self._done.set()
        self._data_ready.set()
        self._space.set()
        if self._keepalive_task is not None and self._keepalive_task is not asyncio.current_task():
            self._keepalive_task.cancel()
        await close_writer(self.writer)

    async def recv(self) -> str | bytes:
        while not self._messages:
            if self._done.is_set():
                raise WSClosed(self.protocol.close_code, self.protocol.close_reason or "")
            self._data_ready.clear()
            await self._data_ready.wait()
        msg = self._messages.popleft()
        self._space.set()
        return msg

    async def send(self, data: str | bytes) -> None:
        if not self.open:
            raise WSClosed(self.protocol.close_code)
        if isinstance(data, str):
            self.protocol.send_text(data.encode("utf-8"))
        else:
            self.protocol.send_binary(data)
        await self._flush()
        if self._done.is_set():
            raise WSClosed(self.protocol.close_code)

    async def close(self, code: int = 1000, reason: str = "", timeout: float | None = None) -> None:
        """Close within `timeout` (default CLOSE_TIMEOUT) seconds in total; abort after that.

        A peer that stops reading cannot hold the connection open: the
        closing frame's flush, the closing handshake and the final transport
        flush all share the one deadline.
        """
        try:
            async with asyncio.timeout(CLOSE_TIMEOUT if timeout is None else timeout):
                if self.protocol.state is State.OPEN:
                    self.protocol.send_close(code, reason)
                    await self._flush()
                if self._reader_task is not None and not self._reader_task.done():
                    self._space.set()
                    # asyncio.wait does not raise if the reader task failed or was cancelled.
                    await asyncio.wait({self._reader_task})
                await self._close_transport()
        except (asyncio.TimeoutError, TimeoutError):
            log.debug("websocket close timed out; aborting the connection")
            abort_writer(self.writer)
        finally:
            if self._reader_task is not None and not self._reader_task.done():
                self._reader_task.cancel()
            if not self._done.is_set():
                self._done.set()
                self._data_ready.set()
                self._space.set()
                abort_writer(self.writer)

    async def wait_closed(self) -> None:
        await self._done.wait()

    def start_keepalive(self, interval: float, timeout: float) -> None:
        """Send WebSocket pings so proxies and NATs keep an idle connection open.

        The connection fails only when it is idle: any received data counts
        as an answer, and no ping can fail while the receive queue is full
        (then the relay itself is not reading, so a pong could not be seen).
        """

        async def run() -> None:
            loop = asyncio.get_running_loop()
            while self.open:
                self._activity.clear()
                await asyncio.sleep(interval)
                if not self.open:
                    return
                if self._activity.is_set() or self._reading_paused:
                    continue  # data arrived, or the peer is waiting for us
                # A pong is received data too, so one event covers both.
                self._activity.clear()
                self.protocol.send_ping(b"")
                deadline = loop.time() + timeout
                try:
                    async with asyncio.timeout_at(deadline):
                        await self._flush()
                        await self._activity.wait()
                except (asyncio.TimeoutError, TimeoutError):
                    if self._reading_paused or self._activity.is_set():
                        continue
                    log.info("websocket keepalive timeout")
                    self.protocol.fail(1011, "keepalive ping timeout")
                    with contextlib.suppress(Exception):
                        for data in self.protocol.data_to_send():
                            if data:
                                self.writer.write(data)
                    if self._reader_task is not None:
                        self._reader_task.cancel()
                    return

        self._keepalive_task = asyncio.create_task(run())
