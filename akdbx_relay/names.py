"""Broker names, secrets and stream ids."""

from __future__ import annotations

import hashlib
import re
import secrets

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
NAME_LENGTH = 12
RESERVED_LABELS = frozenset({"www", "api", "relay", "mail"})
_NAME_RE = re.compile(r"^[a-z2-7]{12}$")
_STREAM_RE = re.compile(r"^[0-9a-f]{32}$")


def new_broker_id() -> str:
    while True:
        candidate = "".join(secrets.choice(ALPHABET) for _ in range(NAME_LENGTH))
        if is_valid_broker_id(candidate):
            return candidate


def is_valid_broker_id(label: str) -> bool:
    return bool(_NAME_RE.match(label)) and label not in RESERVED_LABELS


def broker_id_from_host(host: str, domain: str) -> str | None:
    """Return the broker id for '<id>.<domain>', or None for any other name."""
    host = host.lower().rstrip(".")
    suffix = "." + domain
    if not host.endswith(suffix):
        return None
    label = host[: -len(suffix)]
    if not is_valid_broker_id(label):
        return None
    return label


def new_secret() -> str:
    """A 43-character base64url bearer secret (256 bits)."""
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def new_stream_id() -> str:
    return secrets.token_hex(16)


def is_valid_stream_id(value: str) -> bool:
    return bool(_STREAM_RE.match(value))
