"""Certificate signing request checks.

The relay only forwards a CSR to the CA when it asks for exactly the broker's
own name. Error messages never echo CSR contents.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

MAX_CSR_PEM_BYTES = 16384
RSA_KEY_SIZES = (2048, 3072, 4096)
_ALLOWED_EXTENSIONS = {
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE,
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
}
_ALLOWED_HASHES = (hashes.SHA256, hashes.SHA384, hashes.SHA512)


class CSRError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedCSR:
    pem: bytes
    public_key_sha256: str


def public_key_sha256(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def validate_csr(pem_text: str, expected_name: str) -> ValidatedCSR:
    if not isinstance(pem_text, str) or not pem_text.strip():
        raise CSRError("csr is missing")
    pem = pem_text.encode("ascii", "replace")
    if len(pem) > MAX_CSR_PEM_BYTES:
        raise CSRError("csr is too large")
    if b"-----BEGIN CERTIFICATE REQUEST-----" not in pem:
        raise CSRError("csr must be PEM")
    try:
        csr = x509.load_pem_x509_csr(pem)
    except ValueError:
        raise CSRError("csr cannot be parsed") from None
    try:
        if not csr.is_signature_valid:
            raise CSRError("csr signature is not valid")
    except Exception as exc:  # unsupported algorithms raise here
        if isinstance(exc, CSRError):
            raise
        raise CSRError("csr signature cannot be checked") from None
    if not isinstance(csr.signature_hash_algorithm, _ALLOWED_HASHES):
        raise CSRError("csr signature hash must be SHA-256, SHA-384 or SHA-512")

    key = csr.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise CSRError("EC keys must use P-256")
    elif isinstance(key, rsa.RSAPublicKey):
        if key.key_size not in RSA_KEY_SIZES:
            raise CSRError("RSA keys must be 2048, 3072 or 4096 bits")
    else:
        raise CSRError("key type must be ECDSA P-256 or RSA")

    for attribute in csr.subject:
        if attribute.oid != NameOID.COMMON_NAME:
            raise CSRError("subject may contain only the common name")
        if str(attribute.value).lower() != expected_name:
            raise CSRError("common name must equal the broker name")

    try:
        extensions = csr.extensions
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        raise CSRError("csr extensions cannot be parsed") from None
    san = None
    for ext in extensions:
        if ext.oid not in _ALLOWED_EXTENSIONS:
            raise CSRError("csr requests an extension that is not allowed")
        if ext.oid == ExtensionOID.BASIC_CONSTRAINTS and ext.value.ca:
            raise CSRError("csr must not request a CA certificate")
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            san = ext.value
    if san is None:
        raise CSRError("csr must contain a subjectAltName with the broker name")
    names = list(san)
    if len(names) != 1 or not isinstance(names[0], x509.DNSName):
        raise CSRError("csr must contain exactly one DNS name and no other names")
    if names[0].value.lower() != expected_name:
        raise CSRError("DNS name must equal the broker name")

    canonical = csr.public_bytes(serialization.Encoding.PEM)
    return ValidatedCSR(pem=canonical, public_key_sha256=public_key_sha256(key))
