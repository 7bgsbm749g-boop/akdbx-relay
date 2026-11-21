"""Shared test helpers: certificates, ClientHello bytes, HTTP calls, relay setup."""

from __future__ import annotations

import asyncio
import datetime
import json
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from akdbx_relay.config import Config
from akdbx_relay.relay import Relay
from akdbx_relay.store import Store


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class CA:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "akdbx-relay test CA")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now() - datetime.timedelta(days=1))
            .not_valid_after(now() + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def sign_csr(self, csr: x509.CertificateSigningRequest, days: int = 90) -> x509.Certificate:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now() - datetime.timedelta(minutes=5))
            .not_valid_after(now() + datetime.timedelta(days=days))
            .add_extension(san, critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def leaf(self, name: str) -> tuple[bytes, bytes]:
        """(cert chain PEM, key PEM) for a TLS server named `name`."""
        key = ec.generate_private_key(ec.SECP256R1())
        csr = make_csr(name, key)
        cert = self.sign_csr(csr)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return cert.public_bytes(serialization.Encoding.PEM) + self.pem, key_pem

    def client_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.load_verify_locations(cadata=self.pem.decode())
        return ctx


def make_csr(name: str | None, key=None, *, sans=None, cn: str | None = None, extra_ext=None,
             hash_alg=None) -> x509.CertificateSigningRequest:
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []
    builder = builder.subject_name(x509.Name(attrs))
    if sans is None and name is not None:
        sans = [x509.DNSName(name)]
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if extra_ext is not None:
        builder = builder.add_extension(extra_ext, critical=False)
    alg = hash_alg if hash_alg is not None else hashes.SHA256()
    if alg is False:
        alg = None
    return builder.sign(key, alg)


def csr_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def rsa_key(bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def client_hello(server_name: str | None, *, tls13: bool = True) -> bytes:
    """A real ClientHello from Python's TLS stack."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if not tls13:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


async def http(port: int, method: str, path: str, body: object = None,
               headers: dict[str, str] | None = None, raw_body: bytes | None = None,
               host: str = "127.0.0.1") -> tuple[int, dict[str, str], object]:
    reader, writer = await asyncio.open_connection(host, port)
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else b"")
    lines = [f"{method} {path} HTTP/1.1", "Host: akdbx.link"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if method == "POST" and not any(k.lower() in ("content-length", "transfer-encoding") for k in (headers or {})):
        lines.append(f"Content-Length: {len(data)}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + data)
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), 30)
    writer.close()
    head, _, payload = raw.partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode("latin-1").split("\r\n")
    status = int(status_line.split(" ")[1])
    hdrs = {}
    for line in header_lines:
        k, _, v = line.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    try:
        parsed: object = json.loads(payload) if payload else None
    except ValueError:
        parsed = payload
    return status, hdrs, parsed


def make_config(tmp_path, **overrides) -> Config:
    cfg = Config(
        domain="akdbx.link",
        public_hosts=["127.0.0.1"],
        public_port=0,
        control_host="127.0.0.1",
        control_port=0,
        state_path=str(tmp_path / "relay.sqlite3"),
        acme_account_key_file=str(tmp_path / "acme-account.pem"),
        dns_propagation_seconds=0,
        acme_timeout=30,
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


class FakeIssuer:
    """Signs CSRs with a local CA; counts calls."""

    def __init__(self, ca: CA | None = None) -> None:
        self.ca = ca or CA()
        self.calls: list[str] = []
        self.fail: Exception | None = None

    async def issue(self, name: str, csr_pem_bytes: bytes) -> str:
        self.calls.append(name)
        if self.fail is not None:
            raise self.fail
        csr = x509.load_pem_x509_csr(csr_pem_bytes)
        cert = self.ca.sign_csr(csr)
        return (cert.public_bytes(serialization.Encoding.PEM) + self.ca.pem).decode()

    async def cleanup_stale_records(self) -> None:
        return None


async def start_relay(tmp_path, issuer=None, **overrides) -> Relay:
    cfg = make_config(tmp_path, **overrides)
    relay = Relay(cfg, Store(cfg.state_path), issuer)
    await relay.start()
    return relay
