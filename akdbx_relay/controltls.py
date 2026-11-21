"""The relay's own TLS certificate for the control host name.

Brokers reach the control API at ``https://<control host name>:<public port>``.
The relay terminates those connections itself, so the bearer secrets in them
pass through no third party. The certificate comes from one of two sources:

- operator-supplied files (``AKDBX_RELAY_CONTROL_CERT_FILE`` and
  ``AKDBX_RELAY_CONTROL_KEY_FILE``): the relay loads them at start and again
  when they change;
- by default, the relay's own ACME order (the same DNS-01 code that brokers
  use), with its own ECDSA P-256 key. The key and chain live in the state
  directory with mode 0600, and the relay renews the certificate when less
  than one third of its lifetime remains.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import ssl
from typing import Awaitable, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import Config
from .issuer import IssuanceError

log = logging.getLogger("akdbx_relay.controltls")

# Wait between failed attempts to get the first certificate, doubling.
RETRY_MIN = 60.0
RETRY_MAX = 3600.0
# Longest sleep between checks of a valid certificate.
CHECK_MAX = 12 * 3600.0

IssueFn = Callable[[str, bytes], Awaitable[str]]


class ControlTLSError(Exception):
    """The control certificate files are not usable."""


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _not_before(cert: x509.Certificate) -> datetime.datetime:
    try:
        return cert.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def _not_after(cert: x509.Certificate) -> datetime.datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [n.lower() for n in san.get_values_for_type(x509.DNSName)]


def name_matches(cert: x509.Certificate, hostname: str) -> bool:
    for name in _names(cert):
        if name == hostname:
            return True
        if name.startswith("*.") and "." in hostname and hostname.split(".", 1)[1] == name[2:]:
            return True
    return False


def write_private(path: str, data: bytes) -> None:
    """Write a 0600 file atomically (temporary file, then rename)."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_or_create_key(path: str) -> ec.EllipticCurvePrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ControlTLSError("the control TLS key must be an ECDSA key")
        return key
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    log.info("created a new control TLS key")
    return key


def make_csr(hostname: str, key: ec.EllipticCurvePrivateKey) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def server_context(chain_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(chain_path, key_path)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


class ControlTLS:
    """Holds the current server SSL context for the control host name."""

    def __init__(self, cfg: Config, issue: IssueFn | None,
                 now: Callable[[], datetime.datetime] = _utcnow) -> None:
        self.cfg = cfg
        self.hostname = cfg.control_hostname
        self.chain_path, self.key_path = cfg.control_tls_files
        self.managed = cfg.managed_control_tls
        self._issue = issue
        self._now = now
        self.context: ssl.SSLContext | None = None
        self.not_before: datetime.datetime | None = None
        self.not_after: datetime.datetime | None = None
        self._stamp: tuple[float, float] | None = None
        self.renewals = 0

    # Loading

    def _file_stamp(self) -> tuple[float, float] | None:
        try:
            return (os.stat(self.chain_path).st_mtime, os.stat(self.key_path).st_mtime)
        except OSError:
            return None

    def load(self) -> bool:
        """Load the files if they exist. Returns True when a context is ready.

        Raises ControlTLSError for operator-supplied files that are missing
        or wrong; for relay-managed files it only logs, and a new certificate
        is ordered.
        """
        stamp = self._file_stamp()
        if stamp is None:
            if not self.managed:
                raise ControlTLSError("the control certificate or key file is missing")
            return False
        try:
            with open(self.chain_path, "rb") as fh:
                leaf = x509.load_pem_x509_certificate(fh.read())
            if not name_matches(leaf, self.hostname):
                raise ControlTLSError(f"the control certificate does not name {self.hostname}")
            ctx = server_context(self.chain_path, self.key_path)
        except (OSError, ValueError, ssl.SSLError, ControlTLSError) as exc:
            if not self.managed:
                raise ControlTLSError(f"cannot use the control certificate: {exc}") from None
            log.warning("the stored control certificate is not usable; ordering a new one")
            return False
        self.context = ctx
        self.not_before = _not_before(leaf)
        self.not_after = _not_after(leaf)
        self._stamp = stamp
        if self.not_after <= self._now():
            log.warning("the control certificate has expired")
        return True

    # Renewal

    def renew_at(self) -> datetime.datetime | None:
        if self.not_before is None or self.not_after is None:
            return None
        return self.not_after - (self.not_after - self.not_before) / 3

    def needs_certificate(self) -> bool:
        renew_at = self.renew_at()
        return self.context is None or renew_at is None or self._now() >= renew_at

    async def obtain(self) -> None:
        """Order a certificate with the relay's own key and switch to it."""
        if self._issue is None:
            raise ControlTLSError("certificate issuance is not configured")
        key = load_or_create_key(self.key_path)
        chain = await self._issue(self.hostname, make_csr(self.hostname, key))
        leaf = x509.load_pem_x509_certificate(chain.encode("ascii"))
        if not name_matches(leaf, self.hostname):
            raise ControlTLSError("the issued control certificate names another host")
        write_private(self.chain_path, chain.encode("ascii"))
        if not self.load():
            raise ControlTLSError("the issued control certificate could not be loaded")
        self.renewals += 1
        log.info("installed a control certificate valid until %s", self.not_after.strftime("%Y-%m-%d"))

    def _next_check(self) -> float:
        if not self.managed:
            return 3600.0
        renew_at = self.renew_at()
        if renew_at is None:
            return RETRY_MIN
        wait = (renew_at - self._now()).total_seconds()
        return min(CHECK_MAX, max(RETRY_MIN, wait))

    async def run(self) -> None:
        """Keep the certificate current. Runs until cancelled."""
        if self.managed and self._issue is None:
            if self.context is None:
                log.warning("no control certificate and issuance is not configured: "
                            "the control API is unavailable")
            return
        delay = RETRY_MIN
        while True:
            try:
                if self.managed:
                    if self.needs_certificate():
                        await self.obtain()
                elif self._file_stamp() != self._stamp:
                    self.load()
                    log.info("reloaded the control certificate")
                delay = RETRY_MIN
                wait = self._next_check()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # IssuanceError and ControlTLSError messages are safe to log.
                detail = str(exc) if isinstance(exc, (ControlTLSError, IssuanceError)) else type(exc).__name__
                log.warning("control certificate update failed: %s", detail)
                wait = delay
                delay = min(delay * 2, RETRY_MAX)
            await asyncio.sleep(wait)
