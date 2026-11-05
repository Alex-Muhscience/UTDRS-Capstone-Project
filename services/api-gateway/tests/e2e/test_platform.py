"""The platform console, and the read-only role."""
import base64
import os
import secrets
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from config import settings
from tests.e2e.test_mfa import code

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
PLATFORM = f"{API}/platform"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())


def db(client, work):
    from core.database.connection import get_database

    async def call():
        return await work(get_database())

    return client.portal.call(call)


def sign_up(client, monkeypatch, prefix="pf"):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"{prefix}_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"{prefix}_{suffix}@example.com", "organisation": f"Org {suffix}"})
    token = client.post(f"{API}/auth/login", data=credentials).json()["access_token"]
    return credentials, {"Authorization": f"Bearer {token}"}


@pytest.fixture
def operator(client, monkeypatch):
    """A platform administrator, signed in with an authenticator code."""
    credentials, auth = sign_up(client, monkeypatch, "op")
    secret = client.post(f"{API}/auth/mfa/setup", headers=auth).json()["secret"]
    client.post(f"{API}/auth/mfa/confirm", json={"code": code(secret)}, headers=auth)
    db(client, lambda d: d["users"].update_one({"username": credentials["username"]}, {"$set": {"platform_admin": True}}))
    step = client.post(f"{API}/auth/login", data=credentials).json()
    token = client.post(f"{API}/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": code(secret, 1)}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, credentials


def test_the_console_needs_a_platform_administrator_with_a_second_factor(client, monkeypatch):
    credentials, org_admin = sign_up(client, monkeypatch)
    assert client.get(f"{PLATFORM}/organisations", headers=org_admin).status_code == 403  # an organisation's administrator is not enough
    db(client, lambda d: d["users"].update_one({"username": credentials["username"]}, {"$set": {"platform_admin": True}}))
    refused = client.get(f"{PLATFORM}/organisations", headers=org_admin)
    assert refused.status_code == 403 and refused.headers["X-Platform-MFA-Required"] == "true"  # signed in with a password only


def test_platform_administrators_see_every_organisation(client, monkeypatch, operator):
    auth, _ = operator
    _, other = sign_up(client, monkeypatch)
    client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "x", "source": "s", "description": "d"}, headers=other)
    other_id = client.get(f"{API}/tenants/current", headers=other).json()["id"]
    listed = {o["id"]: o for o in client.get(f"{PLATFORM}/organisations", headers=auth).json()}
    assert other_id in listed and listed[other_id]["people"] == 1 and listed[other_id]["administrators"] == 1 and listed[other_id]["events_last_week"] == 1
    detail = client.get(f"{PLATFORM}/organisations/{other_id}", headers=auth).json()
    assert detail["users"][0]["role"] == "admin"


def test_creating_an_organisation_and_rescuing_one(client, operator):
    auth, _ = operator
    suffix = uuid.uuid4().hex[:6]
    created = client.post(f"{PLATFORM}/organisations", json={"name": f"Clinic {suffix}", "admin_username": f"clin_{suffix}",
                                                                "admin_email": f"clin_{suffix}@example.com"}, headers=auth)
    assert created.status_code == 201, created.text
    body = created.json()
    signed_in = client.post(f"{API}/auth/login", data={"username": f"clin_{suffix}", "password": body["temporary_password"]})
    assert signed_in.status_code == 200 and signed_in.json()["user"]["role"] == "admin"
    rescue = client.post(f"{PLATFORM}/organisations/{body['tenant']['id']}/administrators",
                         json={"username": f"rescue_{suffix}", "email": f"rescue_{suffix}@example.com"}, headers=auth)
    assert rescue.status_code == 201
    # The organisation sees what the platform did to it.
    org = {"Authorization": f"Bearer {signed_in.json()['access_token']}"}
    actions = [e["action"] for e in client.get(f"{API}/audit-log/", params={"action": "platform"}, headers=org).json()]
    assert "platform.administrator_added" in actions and "platform.organisation_created" in actions


def test_suspending_an_organisation_stops_everything_until_reactivated(client, monkeypatch, operator):
    auth, _ = operator
    credentials, other = sign_up(client, monkeypatch)
    other_id = client.get(f"{API}/tenants/current", headers=other).json()["id"]
    key = client.post(f"{API}/api-keys/", json={"name": "forwarder", "scopes": ["events:write"]}, headers=other).json()["key"]
    assert client.patch(f"{PLATFORM}/organisations/{other_id}", json={"suspended": True}, headers=auth).json()["status"] == "suspended"
    from core.services import tenants

    tenants.forget_suspension(other_id)
    assert client.get(f"{API}/auth/me", headers=other).status_code in (401, 403)  # signed out, and refused
    assert client.post(f"{API}/auth/login", data=credentials).status_code == 403
    assert client.get(f"{API}/events/", headers={"Authorization": f"Bearer {key}"}).status_code == 403
    client.patch(f"{PLATFORM}/organisations/{other_id}", json={"suspended": False}, headers=auth)
    tenants.forget_suspension(other_id)
    assert client.post(f"{API}/auth/login", data=credentials).status_code == 200


def test_deleting_an_organisation_removes_its_data(client, monkeypatch, operator):
    auth, _ = operator
    _, other = sign_up(client, monkeypatch)
    tenant = client.get(f"{API}/tenants/current", headers=other).json()
    client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "x", "source": "s", "description": "d"}, headers=other)
    wrong = client.request("DELETE", f"{PLATFORM}/organisations/{tenant['id']}", json={"confirm_name": "nope"}, headers=auth)
    assert wrong.status_code == 409
    gone = client.request("DELETE", f"{PLATFORM}/organisations/{tenant['id']}", json={"confirm_name": tenant["name"]}, headers=auth)
    assert gone.status_code == 200, gone.text
    assert gone.json()["deleted"]["users"] == 1 and gone.json()["deleted"]["events"] == 1
    assert db(client, lambda d: d["events"].count_documents({"tenant_id": tenant["id"]})) == 0
    assert client.get(f"{PLATFORM}/organisations/{tenant['id']}", headers=auth).status_code == 404
    log = client.get(f"{PLATFORM}/audit-log", headers=auth).json()
    assert any(e["action"] == "platform.organisation_deleted" for e in log)


def test_platform_administrators_are_managed_with_care(client, monkeypatch, operator):
    auth, credentials = operator
    other_credentials, _ = sign_up(client, monkeypatch)
    granted = client.put(f"{PLATFORM}/admins", json={"username": other_credentials["username"], "platform_admin": True}, headers=auth).json()
    assert other_credentials["username"] in [a["username"] for a in granted]
    assert client.put(f"{PLATFORM}/admins", json={"username": credentials["username"], "platform_admin": False}, headers=auth).status_code == 409
    client.put(f"{PLATFORM}/admins", json={"username": other_credentials["username"], "platform_admin": False}, headers=auth)


def test_read_only_people_look_but_change_nothing(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch)
    name = f"ro_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "viewer"}, headers=admin).json()
    viewer = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': name, 'password': created['temporary_password']}).json()['access_token']}"}
    assert client.get(f"{API}/alerts/", headers=viewer).status_code == 200
    assert client.get(f"{API}/cases/", headers=viewer).status_code == 200
    refused = client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "x", "source": "s", "description": "d"}, headers=viewer)
    assert refused.status_code == 403 and "Read-only" in refused.json()["detail"]
    assert client.put(f"{API}/auth/me", json={"firstName": "Rae"}, headers=viewer).status_code == 200  # their own profile
    assert client.post(f"{API}/auth/mfa/setup", headers=viewer).status_code == 200  # and their own security
    assert client.get(f"{API}/users/", headers=viewer).status_code == 200
    assert client.patch(f"{API}/users/{created['user']['id']}", json={"role": "admin"}, headers=viewer).status_code == 403
