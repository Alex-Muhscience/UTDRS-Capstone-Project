"""Sessions: refreshed, rotated, ended, and listed."""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId
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


@pytest.fixture
def account(client, monkeypatch):
    """A new organisation's administrator: their credentials."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"ses_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return username, password


def sign_in(client, username, password, agent="Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36"):
    body = client.post(f"{API}/auth/login", data={"username": username, "password": password}, headers={"User-Agent": agent}).json()
    return body, {"Authorization": f"Bearer {body['access_token']}"}


def refresh(client, token):
    return client.post(f"{API}/auth/refresh", json={"refresh_token": token})


def set_session(client, auth, **fields):
    import jwt

    sid = jwt.decode(auth["Authorization"][7:], options={"verify_signature": False})["sid"]

    async def update():
        from core.database.connection import get_database

        await get_database()["sessions"].update_one({"_id": ObjectId(sid)}, {"$set": fields})

    client.portal.call(update)


def test_signing_in_starts_a_session_that_refreshes(client, account):
    body, auth = sign_in(client, *account)
    assert body["refresh_token"] and body["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert client.get(f"{API}/auth/me", headers=auth).status_code == 200

    renewed = refresh(client, body["refresh_token"])
    assert renewed.status_code == 200
    new = renewed.json()
    assert new["access_token"] != body["access_token"] and new["refresh_token"] != body["refresh_token"]
    assert new["user"]["username"] == account[0]
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 200


def test_a_refresh_token_used_twice_ends_the_session(client, account):
    body, auth = sign_in(client, *account)
    first = refresh(client, body["refresh_token"]).json()
    # Someone replays the old refresh token: it was copied, so the session ends for everyone.
    stolen = refresh(client, body["refresh_token"])
    assert stolen.status_code == 401
    assert refresh(client, first["refresh_token"]).status_code == 401
    response = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {first['access_token']}"})
    assert response.status_code == 401 and "used from two places" in response.json()["detail"]
    log = client.get(f"{API}/audit-log/", params={"action": "auth"}, headers=sign_in(client, *account)[1]).json()
    assert any(e["action"] == "auth.session_reuse_detected" for e in log)


def test_signing_out_ends_the_session(client, account):
    body, auth = sign_in(client, *account)
    assert client.post(f"{API}/auth/logout", headers=auth).status_code == 204
    assert client.get(f"{API}/auth/me", headers=auth).status_code == 401
    assert refresh(client, body["refresh_token"]).status_code == 401


def test_idle_and_old_sessions_end(client, account):
    body, auth = sign_in(client, *account)
    set_session(client, auth, last_used_at=datetime.now(timezone.utc) - timedelta(minutes=settings.SESSION_IDLE_MINUTES + 1))
    response = refresh(client, body["refresh_token"])
    assert response.status_code == 401 and "inactivity" in response.json()["detail"]

    body, auth = sign_in(client, *account)
    set_session(client, auth, expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert client.get(f"{API}/auth/me", headers=auth).status_code == 401
    assert "time limit" in refresh(client, body["refresh_token"]).json()["detail"]


def test_seeing_and_ending_your_sessions(client, account):
    _, laptop = sign_in(client, *account)
    phone_body, phone = sign_in(client, *account, agent="Mozilla/5.0 (iPhone; CPU iPhone OS 18_0) Safari/605.1")
    listed = client.get(f"{API}/auth/sessions", headers=laptop).json()
    assert {s["device"] for s in listed} >= {"Chrome on Linux", "Safari on iPhone"}
    current = [s for s in listed if s["current"]]
    assert len(current) == 1 and current[0]["device"] == "Chrome on Linux" and "refresh_hash" not in current[0]

    phone_id = next(s["id"] for s in listed if s["device"] == "Safari on iPhone")
    assert client.delete(f"{API}/auth/sessions/{phone_id}", headers=laptop).status_code == 204
    assert client.get(f"{API}/auth/me", headers=phone).status_code == 401

    _, tablet = sign_in(client, *account)
    assert client.post(f"{API}/auth/sessions/end-others", headers=laptop).json()["ended"] >= 1
    assert client.get(f"{API}/auth/me", headers=tablet).status_code == 401
    assert client.get(f"{API}/auth/me", headers=laptop).status_code == 200


def test_changing_the_password_signs_out_everywhere_else(client, account):
    username, password = account
    _, here = sign_in(client, username, password)
    _, elsewhere = sign_in(client, username, password)
    new_password = secrets.token_urlsafe(16)
    changed = client.post(f"{API}/auth/me/change-password", json={"current_password": password, "new_password": new_password}, headers=here).json()
    assert changed["other_sessions_ended"] >= 1
    assert client.get(f"{API}/auth/me", headers=elsewhere).status_code == 401
    assert client.get(f"{API}/auth/me", headers=here).status_code == 200


def test_administrators_end_other_peoples_sessions(client, account):
    _, admin = sign_in(client, *account)
    name = f"ana_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "analyst"}, headers=admin).json()
    user_id, temporary = created["user"]["id"], created["temporary_password"]

    _, analyst = sign_in(client, name, temporary)
    assert client.post(f"{API}/users/{user_id}/sign-out", headers=admin).json()["ended"] == 1
    assert client.get(f"{API}/auth/me", headers=analyst).status_code == 401
    assert client.post(f"{API}/users/{user_id}/sign-out", headers=analyst).status_code == 401

    _, analyst = sign_in(client, name, temporary)
    reset = client.post(f"{API}/users/{user_id}/reset-password", headers=admin).json()
    assert client.get(f"{API}/auth/me", headers=analyst).status_code == 401

    _, analyst = sign_in(client, name, reset["temporary_password"])
    client.patch(f"{API}/users/{user_id}", json={"active": False}, headers=admin)
    response = client.get(f"{API}/auth/me", headers=analyst)
    assert response.status_code == 401


def test_administrators_acting_on_themselves_stay_signed_in_here(client, account):
    _, here = sign_in(client, *account)
    _, elsewhere = sign_in(client, *account)
    my_id = client.get(f"{API}/auth/me", headers=here).json()["id"]
    assert client.post(f"{API}/users/{my_id}/sign-out", headers=here).json()["ended"] == 1
    assert client.get(f"{API}/auth/me", headers=elsewhere).status_code == 401
    assert client.get(f"{API}/auth/me", headers=here).status_code == 200
    client.post(f"{API}/users/{my_id}/reset-password", headers=here)
    assert client.get(f"{API}/auth/me", headers=here).status_code == 200


def test_sessions_are_your_own(client, account, monkeypatch):
    _, mine = sign_in(client, *account)
    my_id = next(s["id"] for s in client.get(f"{API}/auth/sessions", headers=mine).json() if s["current"])
    username, password = f"ses_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    _, theirs = sign_in(client, username, password)
    assert client.delete(f"{API}/auth/sessions/{my_id}", headers=theirs).status_code == 404
    assert client.get(f"{API}/auth/me", headers=mine).status_code == 200


def test_tokens_without_a_session_are_refused(client, account):
    import jwt

    _, auth = sign_in(client, *account)
    me = client.get(f"{API}/auth/me", headers=auth).json()
    sessionless = jwt.encode({"sub": me["id"], "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {sessionless}"}).status_code == 401
    assert refresh(client, "not-a-real-refresh-token").status_code == 401
