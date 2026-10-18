"""Multi-factor authentication: authenticator codes, recovery codes, and organisations requiring it."""
import base64
import os
import secrets
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())


def step(offset=0):
    from core.services.mfa import STEP_SECONDS

    return int(time.time() // STEP_SECONDS) + offset


def code(secret, offset=0):
    from core.services.mfa import code_at

    return code_at(secret, step(offset))


def new_org(client, monkeypatch):
    """A new organisation's administrator: their credentials and session."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"mfa_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return username, password, sign_in(client, username, password)


def sign_in(client, username, password):
    body = client.post(f"{API}/auth/login", data={"username": username, "password": password}).json()
    return {"Authorization": f"Bearer {body['access_token']}"} if body.get("access_token") else body


def enrol(client, auth):
    secret = client.post(f"{API}/auth/mfa/setup", headers=auth).json()["secret"]
    codes = client.post(f"{API}/auth/mfa/confirm", json={"code": code(secret)}, headers=auth).json()["recovery_codes"]
    return secret, codes


def test_setting_up_and_signing_in_with_a_code(client, monkeypatch):
    username, password, auth = new_org(client, monkeypatch)
    status = client.get(f"{API}/auth/mfa", headers=auth).json()
    assert status == {"enabled": False, "enabled_at": None, "recovery_codes_left": 0, "required_by_organisation": False, "encryption_available": True}

    setup = client.post(f"{API}/auth/mfa/setup", headers=auth).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/UTDRS%20%28Org%20") and f"secret={setup['secret']}" in setup["otpauth_uri"]
    wrong = client.post(f"{API}/auth/mfa/confirm", json={"code": "000000"}, headers=auth)
    assert wrong.status_code == 422 and "not right" in wrong.json()["detail"]
    codes = client.post(f"{API}/auth/mfa/confirm", json={"code": code(setup["secret"])}, headers=auth).json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10
    assert client.get(f"{API}/auth/me", headers=auth).json()["mfa_enabled"] is True

    # The secret is stored encrypted; the codes only as hashes.
    async def stored():
        from core.database.connection import get_database

        return (await get_database()["users"].find_one({"username": username}))["mfa"]

    doc = client.portal.call(stored)
    assert doc["secret"].startswith("v1:") and setup["secret"] not in str(doc) and codes[0] not in str(doc)

    # The password alone is not enough now.
    first = sign_in(client, username, password)
    assert first["mfa_required"] is True and first["access_token"] is None and first["user"] is None
    # The token between the steps is not a session.
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {first['mfa_token']}"}).status_code == 401

    assert client.post(f"{API}/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": "123456"}).status_code == 401
    good = code(setup["secret"], 1)  # the confirm step is used; the next is within the drift allowed
    done = client.post(f"{API}/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": good}).json()
    assert done["access_token"] and done["user"]["username"] == username
    replay = client.post(f"{API}/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": good})
    assert replay.status_code == 401  # each code works once

    # A recovery code works once, too.
    assert client.post(f"{API}/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": codes[0].upper()}).json()["access_token"]
    assert client.post(f"{API}/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": codes[0]}).status_code == 401
    assert client.get(f"{API}/auth/mfa", headers=auth).json()["recovery_codes_left"] == 9

    log = client.get(f"{API}/audit-log/", params={"action": "auth"}, headers=auth).json()
    assert {"auth.mfa_enabled", "auth.mfa_failed", "auth.login_password_accepted"} <= {e["action"] for e in log}
    assert any(e["action"] == "auth.login_succeeded" and (e.get("details") or {}).get("mfa") == "recovery" for e in log)


def test_guessing_codes_is_throttled_and_a_password_does_not_reset_it(client, monkeypatch):
    username, password, auth = new_org(client, monkeypatch)
    enrol(client, auth)
    for _ in range(settings.LOGIN_MAX_FAILURES_PER_ACCOUNT):
        token = sign_in(client, username, password)["mfa_token"]  # the right password each time
        assert client.post(f"{API}/auth/login/mfa", json={"mfa_token": token, "code": "000000"}).status_code == 401
    # Throttled now: the next sign-in is refused before any code, even with the right password.
    response = client.post(f"{API}/auth/login", data={"username": username, "password": password})
    assert response.status_code == 429 and response.headers["Retry-After"]


def test_forged_or_stale_tokens_are_refused(client, monkeypatch):
    import jwt
    from datetime import datetime, timedelta, timezone

    username, password, auth = new_org(client, monkeypatch)
    secret, _ = enrol(client, auth)
    me = client.get(f"{API}/auth/me", headers=auth).json()
    stale = jwt.encode({"sub": me["id"], "purpose": "mfa", "tenant": me["tenant_id"], "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
                       settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    forged = jwt.encode({"sub": me["id"], "purpose": "mfa", "tenant": me["tenant_id"]}, "not-the-secret", algorithm="HS256")
    for token in (stale, forged, sign_in(client, username, password)["mfa_token"] + "x"):
        response = client.post(f"{API}/auth/login/mfa", json={"mfa_token": token, "code": code(secret, 1)})
        assert response.status_code == 401 and "Sign in again" in response.json()["detail"]


def test_an_organisation_can_require_it(client, monkeypatch):
    username, password, admin = new_org(client, monkeypatch)
    response = client.patch(f"{API}/tenants/current/security", json={"require_mfa": True}, headers=admin)
    assert response.status_code == 409 and "for yourself first" in response.json()["detail"]
    secret, _ = enrol(client, admin)
    assert client.patch(f"{API}/tenants/current/security", json={"require_mfa": True}, headers=admin).json()["require_mfa"] is True

    # Someone without MFA can only set it up.
    name = f"ana_{uuid.uuid4().hex[:6]}"
    temporary = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "admin"}, headers=admin).json()["temporary_password"]
    restricted = sign_in(client, name, temporary)
    assert client.get(f"{API}/auth/me", headers=restricted).json()["mfa_setup_required"] is True
    blocked = client.get(f"{API}/alerts/", headers=restricted)
    assert blocked.status_code == 403 and blocked.headers["X-MFA-Setup-Required"] == "true"
    assert client.get(f"{API}/tenants/current", headers=restricted).status_code == 200
    # Not even an administrator can lift the requirement before setting up MFA.
    assert client.patch(f"{API}/tenants/current/security", json={"require_mfa": False}, headers=restricted).status_code == 403

    enrol(client, restricted)
    assert client.get(f"{API}/alerts/", headers=restricted).status_code == 200
    # And nobody turns it off while it is required.
    response = client.post(f"{API}/auth/mfa/disable", json={"code": "000000"}, headers=admin)
    assert response.status_code == 409 and "requires" in response.json()["detail"]


def test_turning_it_off_and_new_recovery_codes(client, monkeypatch):
    username, password, auth = new_org(client, monkeypatch)
    secret, codes = enrol(client, auth)
    fresh = client.post(f"{API}/auth/mfa/recovery-codes", json={"code": code(secret, 1)}, headers=auth).json()["recovery_codes"]
    assert set(fresh).isdisjoint(codes)
    assert client.post(f"{API}/auth/mfa/disable", json={"code": codes[0]}, headers=auth).status_code == 409  # old codes stopped working
    assert client.post(f"{API}/auth/mfa/disable", json={"code": fresh[0]}, headers=auth).status_code == 204
    assert sign_in(client, username, password)["Authorization"]  # the password is enough again


def test_an_administrator_resets_a_lost_phone(client, monkeypatch):
    username, password, admin = new_org(client, monkeypatch)
    name = f"bo_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "analyst"}, headers=admin).json()
    person = sign_in(client, name, created["temporary_password"])
    enrol(client, person)
    assert sign_in(client, name, created["temporary_password"])["mfa_required"] is True
    reset = client.post(f"{API}/users/{created['user']['id']}/reset-mfa", headers=admin).json()
    assert reset["mfa_enabled"] is False
    assert sign_in(client, name, created["temporary_password"])["Authorization"]
    assert client.post(f"{API}/users/{created['user']['id']}/reset-mfa", headers=person).status_code == 403


def test_it_needs_an_encryption_key(client, monkeypatch):
    _, _, auth = new_org(client, monkeypatch)
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
    assert client.get(f"{API}/auth/mfa", headers=auth).json()["encryption_available"] is False
    response = client.post(f"{API}/auth/mfa/setup", headers=auth)
    assert response.status_code == 409 and "ENCRYPTION_KEY" in response.json()["detail"]
