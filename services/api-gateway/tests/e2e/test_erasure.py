"""Erasing a person's personal data on request."""
import os
import secrets
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


@pytest.fixture
def org(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"er_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"er_{suffix}@example.com", "organisation": f"Org {suffix}"})
    admin = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    return admin


def colleague(client, admin):
    name = f"pat_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "analyst", "firstName": "Pat", "lastName": "Lee"}, headers=admin).json()
    token = client.post(f"{API}/auth/login", data={"username": name, "password": created["temporary_password"]}).json()["access_token"]
    return created["user"], {"Authorization": f"Bearer {token}"}


def test_a_person_is_erased_but_the_records_hold_together(client, org):
    from datetime import datetime, timezone

    person, session = colleague(client, org)
    # They work a case: a note in its timeline carries their name.
    event = client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr",
                                                "description": "x", "raw_data": {"user": f"u-{uuid.uuid4().hex[:6]}"}}, headers=org).json()
    alert = client.post(f"{API}/alerts/", json={"title": "x", "description": "x", "severity": "low", "source": "core-engine", "type": "signature",
                                                "event_ids": [event["id"]]}, headers=org).json()
    case_id = client.get(f"{API}/alerts/{alert['id']}", headers=org).json()["case_id"]
    client.post(f"{API}/cases/{case_id}/notes", json={"text": "Looked into it"}, headers=session)

    refused = client.post(f"{API}/users/{person['id']}/erase", json={"confirm_username": "someone else"}, headers=org)
    assert refused.status_code == 422
    erased = client.post(f"{API}/users/{person['id']}/erase", json={"confirm_username": person["username"]}, headers=org)
    assert erased.status_code == 200, erased.text
    body = erased.json()
    assert body["username"].startswith("erased-") and body["email"].startswith("erased-") and body["firstName"] is None and body["active"] is False

    # Signed out, and cannot sign in again.
    assert client.get(f"{API}/auth/me", headers=session).status_code == 401
    # Their name is gone from the case; the note itself stays.
    timeline = client.get(f"{API}/cases/{case_id}", headers=org).json()["timeline"]
    note = next(e for e in timeline if e["kind"] == "note")
    assert note["text"] == "Looked into it" and note["actor"]["name"] == "Erased person"
    # The audit log is untouched, and still verifies.
    assert client.get(f"{API}/audit-log/verify", headers=org).json()["ok"] is True
    assert client.post(f"{API}/users/{person['id']}/erase", json={"confirm_username": body["username"]}, headers=org).status_code == 409


def test_nobody_erases_themselves_or_the_last_administrator(client, org):
    me = client.get(f"{API}/auth/me", headers=org).json()
    refused = client.post(f"{API}/users/{me['id']}/erase", json={"confirm_username": me["username"]}, headers=org)
    assert refused.status_code == 409


def test_only_administrators_erase(client, org):
    person, session = colleague(client, org)
    me = client.get(f"{API}/auth/me", headers=org).json()
    assert client.post(f"{API}/users/{me['id']}/erase", json={"confirm_username": me["username"]}, headers=session).status_code == 403
