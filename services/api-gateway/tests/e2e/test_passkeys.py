"""Passkeys, with a software authenticator standing in for a phone or security key."""
import base64
import hashlib
import json
import os
import secrets
import struct
import uuid

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1/auth"
ORIGIN = "https://dashboard.example"
RP_ID = "dashboard.example"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Authenticator:
    """Creates passkeys and signs with them, as a platform authenticator would."""

    def __init__(self, origin=ORIGIN, rp_id=RP_ID):
        self.origin, self.rp_id = origin, rp_id
        self.keys = {}  # credential id -> (private key, counter)

    def _auth_data(self, flags: int, counter: int, attested: bytes = b"") -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", counter) + attested

    def create(self, options: dict) -> dict:
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        credential_id = secrets.token_bytes(16)
        self.keys[credential_id] = [key, 0]
        attested = bytes(16) + struct.pack(">H", len(credential_id)) + credential_id + cose
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": self._auth_data(0x45, 0, attested)})  # UP, UV, AT
        client_data = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        return {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client_data), "attestationObject": b64(attestation), "transports": ["internal"]},
                "clientExtensionResults": {}}

    def sign(self, options: dict, credential_id: bytes = None, counter: int = None, user_verified=True) -> dict:
        credential_id = credential_id or next(iter(self.keys))
        key, last = self.keys[credential_id]
        counter = last + 1 if counter is None else counter
        self.keys[credential_id][1] = counter
        auth_data = self._auth_data(0x05 if user_verified else 0x01, counter)
        client_data = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        signature = key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client_data), "authenticatorData": b64(auth_data), "signature": b64(signature), "userHandle": None},
                "clientExtensionResults": {}}


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def site(monkeypatch):
    monkeypatch.setattr(settings, "DASHBOARD_URL", ORIGIN)


@pytest.fixture
def person(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"pk_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/register", json={**credentials, "email": f"pk_{suffix}@example.com", "organisation": f"Org {suffix}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/login', data=credentials).json()['access_token']}"}


def add_passkey(client, auth, device, name="Laptop"):
    options = client.post(f"{API}/passkeys/register/options", headers=auth).json()
    assert options["rp"]["id"] == RP_ID and options["authenticatorSelection"]["userVerification"] == "required"
    return client.post(f"{API}/passkeys", json={"credential": device.create(options), "name": name}, headers=auth)


def sign_in(client, device, **signing):
    options = client.post(f"{API}/passkeys/login/options").json()
    return client.post(f"{API}/passkeys/login", json={"credential": device.sign(options, **signing)})


def test_a_passkey_is_added_and_signs_in(client, person):
    device = Authenticator()
    added = add_passkey(client, person, device)
    assert added.status_code == 201, added.text
    assert added.json()["name"] == "Laptop"
    assert [p["name"] for p in client.get(f"{API}/passkeys", headers=person).json()] == ["Laptop"]

    signed_in = sign_in(client, device)
    assert signed_in.status_code == 200, signed_in.text
    me = client.get(f"{API}/me", headers={"Authorization": f"Bearer {signed_in.json()['access_token']}"}).json()
    assert me["username"] == signed_in.json()["user"]["username"]
    assert client.get(f"{API}/passkeys", headers=person).json()[0]["last_used_at"]


def test_a_challenge_works_once(client, person):
    device = Authenticator()
    add_passkey(client, person, device)
    options = client.post(f"{API}/passkeys/login/options").json()
    assert client.post(f"{API}/passkeys/login", json={"credential": device.sign(options)}).status_code == 200
    assert client.post(f"{API}/passkeys/login", json={"credential": device.sign(options)}).status_code == 401


def test_a_look_alike_site_gets_nothing_it_can_use(client, person):
    device = Authenticator()
    add_passkey(client, person, device)
    phished = Authenticator(origin="https://dashboard.example.evil", rp_id="dashboard.example.evil")
    phished.keys = device.keys
    assert sign_in(client, phished).status_code == 401


def test_a_copied_key_is_refused(client, person):
    device = Authenticator()
    add_passkey(client, person, device)
    assert sign_in(client, device, counter=5).status_code == 200
    assert sign_in(client, device, counter=3).status_code == 401  # the counter went back


def test_the_device_must_check_who_it_is(client, person):
    device = Authenticator()
    add_passkey(client, person, device)
    assert sign_in(client, device, user_verified=False).status_code == 401


def test_a_removed_passkey_no_longer_signs_in(client, person):
    device = Authenticator()
    passkey = add_passkey(client, person, device).json()
    assert client.delete(f"{API}/passkeys/{passkey['id']}", headers=person).status_code == 204
    assert sign_in(client, device).status_code == 401
    # Removing every passkey leaves room for others to remove theirs (the index ignores empty lists).
    other = Authenticator()
    add_passkey(client, person, other)
    assert client.delete(f"{API}/passkeys/{b64(next(iter(other.keys)))}", headers=person).status_code == 204


def test_a_passkey_counts_as_the_second_factor(client, person):
    from core.database.connection import get_database

    device = Authenticator()
    add_passkey(client, person, device)
    tenant = client.get("/api/v1/tenants/current", headers=person).json()["id"]

    async def require():
        from bson import ObjectId

        await get_database()["tenants"].update_one({"_id": ObjectId(tenant)}, {"$set": {"security.require_mfa": True}})

    client.portal.call(require)
    token = sign_in(client, device).json()["access_token"]
    assert client.get("/api/v1/alerts/", headers={"Authorization": f"Bearer {token}"}).status_code == 200
