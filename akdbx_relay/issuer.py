"""Certificate issuance through ACME (Let's Encrypt) with the DNS-01 challenge.

The relay never sees a broker's private key: it forwards the broker's CSR to
the ACME server, publishes the DNS-01 TXT record through the Cloudflare API,
and removes the record again when the order ends.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import os

import josepy as jose
from acme import challenges, client, errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import __version__
from .cloudflare import CloudflareDNS
from .config import Config
from .store import Store, TxtMarker

log = logging.getLogger("akdbx_relay.issuer")
# The acme library logs JWS payloads (CSRs) and responses at DEBUG.
logging.getLogger("acme").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Tag on every TXT record the relay creates, so start-up can find its own.
RECORD_COMMENT = "akdbx-relay ACME challenge"
# A relay-owned TXT record older than this many certificate deadlines
# cannot belong to an order that is still running.
STALE_RECORD_AGE_FACTOR = 2
# Shortest time an order needs after the DNS wait (validation, finalization).
MIN_VALIDATION_SECONDS = 5.0


class IssuanceError(Exception):
    """ACME issuance failed. The message is safe to log (no CSR, no secrets)."""


class IssuanceRateLimited(IssuanceError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("ACME rate limit")
        self.retry_after = retry_after


def load_or_create_account_key(path: str) -> rsa.RSAPrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise IssuanceError("the ACME account key must be an RSA key")
        return key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    log.info("created a new ACME account key")
    return key


def leaf_not_after(fullchain_pem: str) -> datetime.datetime:
    cert = x509.load_pem_x509_certificate(fullchain_pem.encode("ascii"))
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _retry_after_from_error(err: messages.Error) -> int:
    return 3600


class ACMEIssuer:
    def __init__(self, cfg: Config, store: Store, dns: CloudflareDNS) -> None:
        self.cfg = cfg
        self.store = store
        self.dns = dns
        self._key: jose.JWKRSA | None = None
        self._account_lock = asyncio.Lock()

    @property
    def _meta_key(self) -> str:
        return "acme_account_uri:" + self.cfg.acme_directory

    def _jwk(self) -> jose.JWKRSA:
        if self._key is None:
            self._key = jose.JWKRSA(key=load_or_create_account_key(self.cfg.acme_account_key_file))
        return self._key

    def _new_client(self, account_uri: str | None, timeout: float = 30.0) -> client.ClientV2:
        verify: object = self.cfg.acme_ca_bundle or True
        net = client.ClientNetwork(
            self._jwk(),
            user_agent=f"akdbx-relay/{__version__}",
            verify_ssl=verify,  # type: ignore[arg-type]  # requests accepts a CA bundle path
            timeout=max(1, min(30, int(timeout))),
        )
        directory = client.ClientV2.get_directory(self.cfg.acme_directory, net)
        acme = client.ClientV2(directory, net)
        if account_uri:
            net.account = messages.RegistrationResource(uri=account_uri, body=messages.Registration())
        return acme

    def _register_sync(self) -> str:
        acme = self._new_client(None)
        contact: tuple[str, ...] = ()
        if self.cfg.acme_email:
            contact = ("mailto:" + self.cfg.acme_email,)
        reg = messages.NewRegistration(contact=contact, terms_of_service_agreed=True)
        try:
            regr = acme.new_account(reg)
            return regr.uri
        except errors.ConflictError as exc:
            return exc.location

    async def _account_uri(self) -> str:
        async with self._account_lock:
            uri = self.store.get_meta(self._meta_key)
            if uri:
                return uri
            uri = await asyncio.to_thread(self._register_sync)
            self.store.set_meta(self._meta_key, uri)
            log.info("registered the ACME account")
            return uri

    async def cleanup_stale_records(self) -> None:
        """Remove TXT records left behind by a crash or a cancelled order.

        Two passes: every cleanup marker in the store (a marker is written
        before the record is created, so a record whose creation was cut off
        is still found by name and value), then every relay-owned
        ``_acme-challenge`` record in the zone that is older than any order
        could be. At start-up no order of this relay is running.
        """
        for marker in self.store.txt_markers():
            try:
                await self._remove_marked(marker)
            except Exception as exc:
                log.warning("could not remove a stale ACME TXT record: %s", exc)
        try:
            records = await self.dns.list_txt()
        except Exception as exc:
            log.warning("could not list ACME TXT records: %s", exc)
            return
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            seconds=STALE_RECORD_AGE_FACTOR * self.cfg.certificate_deadline)
        suffix = "." + self.cfg.domain
        for rec in records:
            name = rec.name.lower().rstrip(".")
            if (rec.comment != RECORD_COMMENT or not name.startswith("_acme-challenge.")
                    or not (name.endswith(suffix) or name == "_acme-challenge" + suffix)):
                continue
            if rec.created is not None and rec.created > cutoff:
                continue  # possibly an order of another relay process that is still running
            try:
                await self.dns.delete_txt(rec.id)
                log.info("removed a stale relay-owned ACME TXT record")
            except Exception as exc:
                log.warning("could not remove a stale ACME TXT record: %s", exc)

    async def _remove_marked(self, marker: TxtMarker) -> None:
        """Delete the record a marker describes, then the marker."""
        if marker.record_id:
            await self.dns.delete_txt(marker.record_id)
        elif marker.name:
            # The create call may or may not have reached Cloudflare.
            for rec in await self.dns.list_txt(marker.name):
                if rec.content.strip('"') == marker.content and rec.comment == RECORD_COMMENT:
                    await self.dns.delete_txt(rec.id)
        self.store.remove_txt_marker(marker.id)

    async def issue(self, name: str, csr_pem: bytes, deadline: float | None = None) -> str:
        """Run one ACME order for `name`. Returns the PEM chain, leaf first.

        `deadline` is an event-loop time; the order gives up when it passes.
        """
        loop = asyncio.get_running_loop()
        if deadline is None:
            deadline = loop.time() + self.cfg.certificate_deadline
        try:
            return await self._issue(name, csr_pem, deadline)
        except IssuanceError:
            raise
        except messages.Error as exc:
            if exc.code == "accountDoesNotExist":
                self.store.set_meta(self._meta_key, "")
            if exc.code == "rateLimited":
                raise IssuanceRateLimited(_retry_after_from_error(exc)) from None
            raise IssuanceError(f"ACME error {exc.code or exc.typ}") from None
        except errors.ValidationError:
            raise IssuanceError("ACME challenge validation failed") from None
        except errors.TimeoutError:
            raise IssuanceError("ACME order timed out") from None
        except Exception as exc:
            raise IssuanceError(f"ACME failure: {type(exc).__name__}") from None

    async def _issue(self, name: str, csr_pem: bytes, deadline: float) -> str:
        loop = asyncio.get_running_loop()

        def remaining() -> float:
            return deadline - loop.time()

        if remaining() < self.cfg.dns_propagation_seconds + MIN_VALIDATION_SECONDS:
            raise IssuanceError("not enough time left for an ACME order")
        uri = await self._account_uri()
        acme = await asyncio.to_thread(self._new_client, uri, remaining())
        key = self._jwk()
        orderr = await asyncio.to_thread(acme.new_order, csr_pem)
        markers: list[TxtMarker] = []
        unsure: set[int] = set()  # markers whose create call was cut off and may still run
        try:
            answers = []
            for authz in orderr.authorizations:
                if authz.body.status == messages.STATUS_VALID:
                    continue
                identifier = authz.body.identifier.value.lower()
                if identifier != name:
                    raise IssuanceError("ACME order names an unexpected identifier")
                chall = next(
                    (c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01)),
                    None,
                )
                if chall is None:
                    raise IssuanceError("ACME server offered no DNS-01 challenge")
                record_name = chall.chall.validation_domain_name(identifier)
                value = chall.chall.validation(key)
                # The marker is stored before the record exists: if this task
                # is cancelled while Cloudflare creates it, the next start
                # still finds and removes it.
                marker = self.store.add_txt_marker(record_name, value)
                markers.append(marker)
                try:
                    record_id = await self.dns.create_txt(record_name, value, RECORD_COMMENT)
                except asyncio.CancelledError:
                    unsure.add(marker.id)
                    raise
                self.store.set_txt_marker_record(marker.id, record_id)
                markers[-1] = TxtMarker(marker.id, record_name, value, record_id)
                answers.append(chall)
            if markers and self.cfg.dns_propagation_seconds > 0:
                await asyncio.sleep(self.cfg.dns_propagation_seconds)
            for chall in answers:
                await asyncio.to_thread(acme.answer_challenge, chall, chall.chall.response(key))
            wait = min(self.cfg.acme_timeout, remaining())
            if wait <= 0:
                raise IssuanceError("the certificate request deadline passed")
            poll_deadline = datetime.datetime.now() + datetime.timedelta(seconds=wait)
            orderr = await asyncio.to_thread(acme.poll_and_finalize, orderr, poll_deadline)
        finally:
            for marker in markers:
                if marker.id in unsure:
                    continue  # the next start removes it
                try:
                    await self._remove_marked(marker)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # The marker stays in the store; the record is removed at the next start.
                    log.warning("could not remove an ACME TXT record: %s", exc)
        if not orderr.fullchain_pem:
            raise IssuanceError("ACME order returned no certificate")
        return orderr.fullchain_pem
