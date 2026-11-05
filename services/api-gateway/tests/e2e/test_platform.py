"""The operator console (operators apart from every organisation), and the read-only role."""
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
AUTH = f"{PLATFORM}/auth"


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


def new_operator(client, username=None, password=None):
    """An operator account (as another operator, or the settings, would create it), not yet signed in."""
    from core.services import operators

    username = username or f"op_{uuid.uuid4().hex[:6]}"
    password = password or secrets.token_urlsafe(16)
    client.portal.call(lambda: operators.create(username, f"{username}@operators.example", password, None, must_change=False))
    return {"username": username, "password": password}


def operator_sign_in(client, credentials, secret=None, offset=0):
    """Sign an operator in; the first time, set up their authenticator. Returns (headers, secret, response)."""
    step = client.post(f"{AUTH}/login", json=credentials).json()
    if step["step"] == "enrol":
        secret = step["secret"]
        signed = client.post(f"{AUTH}/enrol", json={"step_token": step["step_token"], "code": code(secret, offset)})
    else:
        signed = client.post(f"{AUTH}/mfa", json={"step_token": step["step_token"], "code": code(secret, offset)})
    return {"Authorization": f"Bearer {signed.json()['access_token']}"}, secret, signed


@pytest.fixture
def operator(client):
    """A platform operator, signed in with their authenticator."""
    credentials = new_operator(client)
    auth, _, _ = operator_sign_in(client, credentials)
    return auth, credentials


def test_organisations_accounts_never_reach_the_console(client, monkeypatch):
    credentials, org_admin = sign_up(client, monkeypatch)
    for path in ("/organisations", "/operators", "/audit-log"):
        assert client.get(f"{PLATFORM}{path}", headers=org_admin).status_code == 401  # not even an administrator's token
    # Nor can an organisation's account sign in to the console, or a flag on it make it an operator.
    assert client.post(f"{AUTH}/login", json=credentials).status_code == 401
    db(client, lambda d: d["users"].update_one({"username": credentials["username"]}, {"$set": {"platform_admin": True}}))
    assert client.get(f"{PLATFORM}/organisations", headers=org_admin).status_code == 401


def test_operators_sign_in_apart_with_an_authenticator_they_must_set_up(client):
    credentials = new_operator(client)
    assert client.post(f"{AUTH}/login", json={**credentials, "password": "wrong"}).status_code == 401
    first = client.post(f"{AUTH}/login", json=credentials).json()
    assert first["step"] == "enrol" and first["secret"] and first["otpauth_uri"].startswith("otpauth://totp/")
    assert client.post(f"{AUTH}/enrol", json={"step_token": first["step_token"], "code": "000000"}).status_code == 401
    auth, secret, signed = operator_sign_in(client, credentials)
    assert signed.status_code == 200 and len(signed.json()["recovery_codes"]) == 10
    assert client.get(f"{PLATFORM}/organisations", headers=auth).status_code == 200
    # Their token is for the platform only: the organisations' API refuses it.
    assert client.get(f"{API}/auth/me", headers=auth).status_code == 401
    assert client.get(f"{API}/alerts/", headers=auth).status_code == 401
    # Next time, a code; a recovery code works once.
    again = client.post(f"{AUTH}/login", json=credentials).json()
    assert again["step"] == "mfa"
    recovery = signed.json()["recovery_codes"][0]
    assert client.post(f"{AUTH}/mfa", json={"step_token": again["step_token"], "code": recovery}).status_code == 200
    assert client.post(f"{AUTH}/mfa", json={"step_token": again["step_token"], "code": recovery}).status_code == 401
    # Signing out ends the session.
    assert client.post(f"{AUTH}/logout", headers=auth).status_code == 204
    assert client.get(f"{PLATFORM}/organisations", headers=auth).status_code == 401


def test_operator_sessions_end_when_idle(client, operator):
    from datetime import timedelta

    auth, _ = operator
    refreshed = client.post(f"{AUTH}/refresh", headers=auth)
    assert refreshed.status_code == 200
    from utils.time import utcnow

    db(client, lambda d: d["operator_sessions"].update_many({"ended_at": None}, {"$set": {"last_seen_at": utcnow() - timedelta(hours=1)}}))
    ended = client.get(f"{PLATFORM}/organisations", headers=auth)
    assert ended.status_code == 401 and "without use" in ended.json()["detail"]


def test_operators_see_every_organisation(client, monkeypatch, operator):
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


def test_operators_manage_each_other_with_care(client, operator):
    auth, credentials = operator
    me = client.get(f"{AUTH}/me", headers=auth).json()
    suffix = uuid.uuid4().hex[:6]
    added = client.post(f"{PLATFORM}/operators", json={"username": f"new_{suffix}", "email": f"new_{suffix}@operators.example"}, headers=auth)
    assert added.status_code == 201
    new = added.json()
    # A temporary password: they set up an authenticator, then must choose a password before anything else.
    new_auth, secret, _ = operator_sign_in(client, {"username": f"new_{suffix}", "password": new["temporary_password"]})
    refused = client.get(f"{PLATFORM}/organisations", headers=new_auth)
    assert refused.status_code == 403 and refused.headers["X-Password-Change-Required"] == "true"
    assert client.post(f"{AUTH}/password", json={"current_password": new["temporary_password"], "new_password": "short"}, headers=new_auth).status_code == 422
    assert client.post(f"{AUTH}/password", json={"current_password": new["temporary_password"], "new_password": "a-much-longer-password"},
                       headers=new_auth).status_code == 204
    assert client.get(f"{PLATFORM}/organisations", headers=new_auth).status_code == 200

    assert client.patch(f"{PLATFORM}/operators/{me['id']}", json={"active": False}, headers=auth).status_code == 409  # not yourself
    assert client.post(f"{PLATFORM}/operators/{me['id']}/reset", headers=auth).status_code == 409
    reset = client.post(f"{PLATFORM}/operators/{new['operator']['id']}/reset", headers=auth)
    assert reset.status_code == 200 and reset.json()["operator"]["mfa"] is False
    assert client.get(f"{PLATFORM}/organisations", headers=new_auth).status_code == 401  # their sessions ended
    assert client.patch(f"{PLATFORM}/operators/{new['operator']['id']}", json={"active": False}, headers=auth).json()["active"] is False
    assert client.post(f"{AUTH}/login", json={"username": f"new_{suffix}", "password": reset.json()["temporary_password"]}).status_code == 401
    actions = [e["action"] for e in client.get(f"{PLATFORM}/audit-log", headers=auth).json()]
    assert {"platform.operator_added", "platform.operator_reset", "platform.operator_deactivated", "platform.signed_in"} <= set(actions)


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
