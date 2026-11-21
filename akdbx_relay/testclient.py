"""Reference broker client for the akdbx relay protocol (v1).

It registers with a relay, keeps the control WebSocket open, and splices each
announced stream to a local TLS server. akdbx's own broker implements the
same protocol; this module exists for tests and for manual checks of a relay
deployment:

    python -m akdbx_relay.testclient --relay https://akdbx.link --state ./broker.json demo

The demo command registers (once), creates an ECDSA P-256 key and CSR, gets
a certificate, serves a small HTTPS page on 127.0.0.1, and prints the public
URL. The secret stays in the state file (mode 0600) and is never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import random
import ssl
import urllib.error
import urllib.request

import websockets
from websockets.asyncio.client import connect

log = logging.getLogger("akdbx_relay.testclient")
logging.getLogger("websockets").setLevel(logging.WARNING)


class RelayAPIError(Exception):
    def __init__(self, status: int, body: dict) -> None:
        super().__init__(f"HTTP {status}: {body.get('error')}")
        self.status = status
        self.body = body


def _post_json(url: str, body: dict, secret: str | None = None,
               ssl_context: ssl.SSLContext | None = None, timeout: float = 120) -> dict:
    headers = {"Content-Type": "application/json", "User-Agent": "akdbx-relay-testclient"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    req = urllib.request.Request(url, json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except ValueError:
            payload = {}
        raise RelayAPIError(exc.code, payload) from None


async def register(relay_url: str, client: str = "akdbx-relay-testclient/1",
                   ssl_context: ssl.SSLContext | None = None) -> dict:
    return await asyncio.to_thread(
        _post_json, relay_url.rstrip("/") + "/api/v1/register",
        {"protocol": 1, "client": client}, None, ssl_context,
    )


async def request_certificate(relay_url: str, secret: str, csr_pem: str,
                              ssl_context: ssl.SSLContext | None = None) -> dict:
    return await asyncio.to_thread(
        _post_json, relay_url.rstrip("/") + "/api/v1/certificate",
        {"csr": csr_pem}, secret, ssl_context,
    )


def _ws_base(relay_url: str) -> str:
    url = relay_url.rstrip("/")
    if url.startswith("https://"):
        return "wss://" + url[len("https://"):]
    if url.startswith("http://"):
        return "ws://" + url[len("http://"):]
    raise ValueError("relay URL must start with http:// or https://")


class BrokerClient:
    """Keeps the control channel up and splices streams to local_host:local_port."""

    def __init__(self, relay_url: str, secret: str, local_port: int, local_host: str = "127.0.0.1",
                 ssl_context: ssl.SSLContext | None = None) -> None:
        self.ws_base = _ws_base(relay_url)
        self._secret = secret
        self.local_host = local_host
        self.local_port = local_port
        self.ssl_context = ssl_context
        self.connected = asyncio.Event()
        self.streams_opened = 0
        self.control: websockets.asyncio.client.ClientConnection | None = None
        self._tasks: set[asyncio.Task] = set()
        self._stopping = False

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._secret}"}

    def _connect(self, path: str):
        kwargs = {"additional_headers": self._headers(), "max_size": 1 << 20, "open_timeout": 10}
        if self.ws_base.startswith("wss://"):
            kwargs["ssl"] = self.ssl_context or ssl.create_default_context()
        return connect(self.ws_base + path, **kwargs)

    async def run(self) -> None:
        delay = 1.0
        while not self._stopping:
            try:
                async with self._connect("/api/v1/connect") as ws:
                    self.control = ws
                    self.connected.set()
                    delay = 1.0
                    async for message in ws:
                        if isinstance(message, bytes):
                            continue
                        msg = json.loads(message)
                        if msg.get("type") == "ping":
                            await ws.send('{"type":"pong"}')
                        elif msg.get("type") == "open":
                            task = asyncio.create_task(self._stream(msg["stream"]))
                            self._tasks.add(task)
                            task.add_done_callback(self._tasks.discard)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.info("control connection lost: %s", type(exc).__name__)
            finally:
                self.control = None
                self.connected.clear()
            if self._stopping:
                break
            await asyncio.sleep(delay * random.uniform(0.5, 1.0))
            delay = min(delay * 2, 60.0)

    async def stop(self) -> None:
        self._stopping = True
        if self.control is not None:
            await self.control.close()
        for task in list(self._tasks):
            task.cancel()

    async def _stream(self, stream_id: str) -> None:
        self.streams_opened += 1
        try:
            async with self._connect(f"/api/v1/stream/{stream_id}") as ws:
                reader, writer = await asyncio.open_connection(self.local_host, self.local_port)
                try:
                    await _splice_ws_tcp(ws, reader, writer)
                finally:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.info("stream ended: %s", type(exc).__name__)


async def _splice_ws_tcp(ws, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    async def ws_to_tcp() -> None:
        async for message in ws:
            if isinstance(message, str):
                return
            writer.write(message)
            await writer.drain()

    async def tcp_to_ws() -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            await ws.send(data)

    tasks = [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await ws.close()


# Manual demo


def make_key_and_csr(name: str) -> tuple[bytes, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


async def _demo(relay_url: str, state_path: str, local_port: int) -> None:
    if os.path.exists(state_path):
        with open(state_path) as fh:
            state = json.load(fh)
    else:
        state = await register(relay_url)
        _write_private(state_path, json.dumps(state).encode())
    name = state["name"]
    key_path = state_path + ".key.pem"
    cert_path = state_path + ".chain.pem"
    if not os.path.exists(cert_path):
        key_pem, csr_pem = make_key_and_csr(name)
        result = await request_certificate(relay_url, state["secret"], csr_pem)
        _write_private(key_path, key_pem)
        _write_private(cert_path, result["certificate"].encode())
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)

    async def page(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            body = b"akdbx relay test broker: TLS ends here, in the broker.\n"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(page, "127.0.0.1", local_port, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    client = BrokerClient(relay_url, state["secret"], port)
    print(f"public URL: https://{name}:{state['public_port']}/")
    await client.run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m akdbx_relay.testclient")
    parser.add_argument("--relay", default="https://akdbx.link")
    parser.add_argument("--state", required=True, help="private state file (created with mode 0600)")
    parser.add_argument("--local-port", type=int, default=0)
    parser.add_argument("command", choices=["demo"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(_demo(args.relay, args.state, args.local_port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
