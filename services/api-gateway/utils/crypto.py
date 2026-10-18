"""
Encrypting secrets stored in the database, such as a connector's client secret.

AES-256-GCM, with the key from ENCRYPTION_KEY (32 random bytes, base64). Each value
records which key encrypted it, so the key can be rotated: set the new key as
ENCRYPTION_KEY and the old one as ENCRYPTION_KEY_PREVIOUS; values are read with either,
and re-encrypted with the new one when next saved. The record's id is bound to the
ciphertext (associated data), so an encrypted value cannot be moved to another record.

Without ENCRYPTION_KEY, nothing secret can be stored: encrypt() raises, and the features
that need it say so.
"""
import base64
import hashlib
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import settings

VERSION = "v1"


class EncryptionUnavailable(RuntimeError):
    """ENCRYPTION_KEY is not set, or is not a valid key."""


class DecryptionFailed(RuntimeError):
    """The value was not encrypted with a key UTDRS has, or was altered."""


def _key(encoded: Optional[str]) -> Optional[bytes]:
    if not encoded:
        return None
    try:
        key = base64.b64decode(encoded, validate=True)
    except ValueError as e:
        raise EncryptionUnavailable("ENCRYPTION_KEY is not valid base64") from e
    if len(key) != 32:
        raise EncryptionUnavailable("ENCRYPTION_KEY must be 32 bytes (base64 of 32 random bytes)")
    return key


def _key_id(key: bytes) -> str:
    """A short, non-secret name for a key, to know which one encrypted a value."""
    return hashlib.sha256(b"utdrs-key-id:" + key).hexdigest()[:8]


def available() -> bool:
    try:
        return _key(settings.ENCRYPTION_KEY) is not None
    except EncryptionUnavailable:
        return False


def encrypt(plaintext: str, context: str) -> str:
    """Encrypt `plaintext`, bound to `context` (such as the record it belongs to)."""
    key = _key(settings.ENCRYPTION_KEY)
    if key is None:
        raise EncryptionUnavailable("Set ENCRYPTION_KEY to store secrets (32 random bytes, base64)")
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
    return f"{VERSION}:{_key_id(key)}:{base64.b64encode(nonce + sealed).decode('ascii')}"


def decrypt(value: str, context: str) -> str:
    try:
        version, key_id, payload = value.split(":", 2)
    except ValueError as e:
        raise DecryptionFailed("Not an encrypted value") from e
    if version != VERSION:
        raise DecryptionFailed(f"Unknown encryption version {version}")
    for encoded in (settings.ENCRYPTION_KEY, settings.ENCRYPTION_KEY_PREVIOUS):
        key = _key(encoded)
        if key is not None and _key_id(key) == key_id:
            data = base64.b64decode(payload)
            try:
                return AESGCM(key).decrypt(data[:12], data[12:], context.encode("utf-8")).decode("utf-8")
            except InvalidTag as e:
                raise DecryptionFailed("The value was altered, or belongs to another record") from e
    raise DecryptionFailed("Encrypted with a key UTDRS no longer has (set it as ENCRYPTION_KEY_PREVIOUS)")


def needs_rotation(value: str) -> bool:
    key = _key(settings.ENCRYPTION_KEY)
    return key is not None and not value.startswith(f"{VERSION}:{_key_id(key)}:")
