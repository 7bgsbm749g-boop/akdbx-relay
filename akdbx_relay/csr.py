"""Certificate signing request checks.

A broker sends a CSR (never a private key). The relay accepts it only if it
names exactly the broker's own host name, so a broker cannot use the relay
to obtain certificates for any other name.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

MAX_CSR_PEM_BYTES = 16 * 1024
RSA_KEY_SIZES = (2048, 3072, 4096)
_EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14"
_ALLOWED_EXTENSIONS = {
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE,
    ExtensionOID.BASIC_CONSTRAINTS,
}


class CSRError(ValueError):
    """The CSR is not acceptable. The message is safe to return to the client."""


def validate_csr(pem: str, expected_name: str) -> bytes:
    """Check a PEM CSR for `expected_name`. Returns the PEM bytes to send to ACME."""
    if not isinstance(pem, str) or not pem.strip():
        raise CSRError("csr must be a PEM string")
    data = pem.encode("ascii", errors="strict") if pem.isascii() else None
    if data is None:
        raise CSRError("csr must be ASCII PEM")
    if len(data) > MAX_CSR_PEM_BYTES:
        raise CSRError("csr is too large")
    if data.count(b"-----BEGIN CERTIFICATE REQUEST-----") != 1:
        raise CSRError("csr must contain exactly one CERTIFICATE REQUEST block")
    try:
        csr = x509.load_pem_x509_csr(data)
    except Exception as exc:  # cryptography raises ValueError and others
        raise CSRError("csr could not be parsed") from exc
    try:
        if not csr.is_signature_valid:
            raise CSRError("csr signature is not valid")
    except CSRError:
        raise
    except Exception as exc:
        raise CSRError("csr signature could not be checked") from exc

    try:
        key = csr.public_key()
    except Exception as exc:
        raise CSRError("csr public key is not supported") from exc
    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise CSRError("ECDSA keys must use P-256")
    elif isinstance(key, rsa.RSAPublicKey):
        if key.key_size not in RSA_KEY_SIZES:
            raise CSRError("RSA keys must be 2048, 3072 or 4096 bits")
    else:
        raise CSRError("key must be ECDSA P-256 or RSA 2048 or larger")

    for attr in csr.subject:
        if attr.oid != NameOID.COMMON_NAME:
            raise CSRError("subject may contain only a common name")
        if str(attr.value).lower() != expected_name:
            raise CSRError("subject common name must equal the broker name")

    try:
        extensions = list(csr.extensions)
    except Exception as exc:
        raise CSRError("csr extensions could not be parsed") from exc
    san = None
    for ext in extensions:
        if ext.oid not in _ALLOWED_EXTENSIONS:
            raise CSRError("csr contains an extension that is not allowed")
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            san = ext.value
        if ext.oid == ExtensionOID.BASIC_CONSTRAINTS and ext.value.ca:
            raise CSRError("csr must not request a CA certificate")
    if san is None:
        raise CSRError("csr must contain a subjectAltName extension")
    names = list(san)
    if len(names) != 1:
        raise CSRError("csr must contain exactly one subjectAltName entry")
    entry = names[0]
    if not isinstance(entry, x509.DNSName):
        raise CSRError("the subjectAltName entry must be a DNS name")
    if entry.value.lower() != expected_name:
        raise CSRError("the DNS name must equal the broker name")
    try:
        attributes = list(csr.attributes)
    except Exception as exc:
        raise CSRError("csr attributes could not be parsed") from exc
    for attr in attributes:
        # Only the extensionRequest attribute (which carries the SAN) is allowed.
        if attr.oid.dotted_string != _EXTENSION_REQUEST_OID:
            raise CSRError("csr contains an attribute that is not allowed")
    return data
