"""Encrypting stored secrets."""
import base64
import os

import pytest

from config import settings
from utils import crypto


def new_key():
    return base64.b64encode(os.urandom(32)).decode()


@pytest.fixture
def key(monkeypatch):
    value = new_key()
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", value)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY_PREVIOUS", None)
    return value


def test_a_secret_round_trips_and_is_not_readable(key):
    sealed = crypto.encrypt("hunter2-secret", "m365:tenant-a")
    assert sealed.startswith("v1:") and "hunter2" not in sealed
    assert crypto.decrypt(sealed, "m365:tenant-a") == "hunter2-secret"
    assert crypto.encrypt("hunter2-secret", "m365:tenant-a") != sealed  # a fresh nonce every time


def test_a_secret_cannot_be_moved_to_another_record_or_altered(key):
    sealed = crypto.encrypt("hunter2-secret", "m365:tenant-a")
    with pytest.raises(crypto.DecryptionFailed):
        crypto.decrypt(sealed, "m365:tenant-b")
    version, key_id, payload = sealed.split(":")
    data = bytearray(base64.b64decode(payload))
    data[-1] ^= 1
    with pytest.raises(crypto.DecryptionFailed):
        crypto.decrypt(f"{version}:{key_id}:{base64.b64encode(bytes(data)).decode()}", "m365:tenant-a")


def test_keys_can_be_rotated(key, monkeypatch):
    sealed = crypto.encrypt("hunter2-secret", "ctx")
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", new_key())
    with pytest.raises(crypto.DecryptionFailed, match="ENCRYPTION_KEY_PREVIOUS"):
        crypto.decrypt(sealed, "ctx")
    monkeypatch.setattr(settings, "ENCRYPTION_KEY_PREVIOUS", key)
    assert crypto.decrypt(sealed, "ctx") == "hunter2-secret" and crypto.needs_rotation(sealed)
    assert not crypto.needs_rotation(crypto.encrypt("hunter2-secret", "ctx"))


def test_without_a_key_nothing_is_stored(monkeypatch):
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
    assert crypto.available() is False
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.encrypt("x", "ctx")
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(b"short").decode())
    assert crypto.available() is False
