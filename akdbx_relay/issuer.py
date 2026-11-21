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
import threading

import josepy as jose
from acme import challenges, client, errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import __version__
from .cloudflare import CloudflareDNS
from .config import Config
from .store import Store

log = logging.getLogger("akdbx_relay.issuer")
# The acme library logs JWS payloads (CSRs) and responses at DEBUG.
logging.getLogger("acme").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


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
        self._thread_lock = threading.Lock()

    @property
    def _meta_key(self) -> str:
        return "acme_account_uri:" + self.cfg.acme_directory

    def _jwk(self) -> jose.JWKRSA:
        if self._key is None:
            self._key = jose.JWKRSA(key=load_or_create_account_key(self.cfg.acme_account_key_file))
        return self._key

    def _new_client(self, account_uri: str | None) -> client.ClientV2:
        verify: object = self.cfg.acme_ca_bundle or True
        net = client.ClientNetwork(
            self._jwk(),
            user_agent=f"akdbx-relay/{__version__}",
            verify_ssl=verify,  # type: ignore[arg-type]  # requests accepts a CA bundle path
            timeout=30,
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
        """Remove TXT records left behind by a crash during an earlier order."""
        for record_id in self.store.txt_records():
            try:
                await self.dns.delete_txt(record_id)
                self.store.remove_txt_record(record_id)
            except Exception as exc:
                log.warning("could not remove a stale ACME TXT record: %s", exc)

    async def issue(self, name: str, csr_pem: bytes) -> str:
        """Run one ACME order for `name`. Returns the PEM chain, leaf first."""
        try:
            return await self._issue(name, csr_pem)
        except IssuanceError:
            raise
        except messages.Error as exc:
            if exc.code == "rateLimited":
                raise IssuanceRateLimited(_retry_after_from_error(exc)) from None
            raise IssuanceError(f"ACME error {exc.code or exc.typ}") from None
        except errors.ValidationError:
            raise IssuanceError("ACME challenge validation failed") from None
        except errors.TimeoutError:
            raise IssuanceError("ACME order timed out") from None
        except Exception as exc:
            raise IssuanceError(f"ACME failure: {type(exc).__name__}") from None

    async def _issue(self, name: str, csr_pem: bytes) -> str:
        uri = await self._account_uri()
        acme = await asyncio.to_thread(self._new_client, uri)
        key = self._jwk()
        orderr = await asyncio.to_thread(acme.new_order, csr_pem)
        created: list[str] = []
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
                record_id = await self.dns.create_txt(record_name, chall.chall.validation(key))
                created.append(record_id)
                self.store.add_txt_record(record_id)
                answers.append(chall)
            if created and self.cfg.dns_propagation_seconds > 0:
                await asyncio.sleep(self.cfg.dns_propagation_seconds)
            for chall in answers:
                await asyncio.to_thread(acme.answer_challenge, chall, chall.chall.response(key))
            deadline = datetime.datetime.now() + datetime.timedelta(seconds=self.cfg.acme_timeout)
            orderr = await asyncio.to_thread(acme.poll_and_finalize, orderr, deadline)
        finally:
            for record_id in created:
                try:
                    await self.dns.delete_txt(record_id)
                    self.store.remove_txt_record(record_id)
                except Exception as exc:
                    # The record stays in the store and is removed at the next start.
                    log.warning("could not remove an ACME TXT record: %s", exc)
        if not orderr.fullchain_pem:
            raise IssuanceError("ACME order returned no certificate")
        return orderr.fullchain_pem
