"""Custom roles: an organisation's own roles, area by area."""
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from tests.e2e.test_live import a_minute_ago, read, short_streams  # noqa: F401  (fixture)
from tests.e2e.test_platform import key, sign_up  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def person(client, admin, role, custom_role_id=None):
    name = f"rl_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": role,
                                                 **({"custom_role_id": custom_role_id} if custom_role_id else {})}, headers=admin)
    assert created.status_code == 201, created.text
    token = client.post(f"{API}/auth/login", data={"username": name, "password": created.json()["temporary_password"]}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, created.json()["user"]


def new_alert(client, auth):
    return client.post(f"{API}/alerts/", json={"title": f"A {uuid.uuid4().hex[:4]}", "description": "x", "severity": "high", "source": "x", "type": "x"}, headers=auth)


def test_administrators_make_roles_from_permissions(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "ra")
    catalogue = client.get(f"{API}/roles/permissions", headers=admin).json()
    assert {"area": "rules", "label": "Detection rules", "read": "See detection rules", "write": None} in catalogue["areas"]
    assert [r["role"] for r in catalogue["built_in"]] == ["admin", "analyst", "viewer"]

    role = client.post(f"{API}/roles", json={"name": "Triage", "description": "First line", "permissions": ["alerts:write", "cases:read"]}, headers=admin)
    assert role.status_code == 201
    assert role.json()["permissions"] == ["alerts:read", "alerts:write", "cases:read"]  # changing includes seeing
    assert client.post(f"{API}/roles", json={"name": "Triage", "permissions": []}, headers=admin).status_code == 409
    refused = client.post(f"{API}/roles", json={"name": "Rule writer", "permissions": ["rules:write"]}, headers=admin)
    assert refused.status_code == 409 and "rules:write" in refused.json()["detail"]  # administrators' work stays theirs

    analyst, _ = person(client, admin, "analyst")
    assert client.post(f"{API}/roles", json={"name": "Mine", "permissions": []}, headers=analyst).status_code == 403
    assert [r["name"] for r in client.get(f"{API}/roles", headers=analyst).json()] == ["Triage"]


def test_people_with_a_role_can_do_exactly_what_it_permits(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "rb")
    role = client.post(f"{API}/roles", json={"name": "Triage", "permissions": ["alerts:write", "cases:read"]}, headers=admin).json()
    triage, account = person(client, admin, "custom", role["id"])
    assert account["role"] == "custom" and account["custom_role_id"] == role["id"]
    me = client.get(f"{API}/auth/me", headers=triage).json()
    assert me["custom_role_name"] == "Triage" and me["permissions"] == ["alerts:read", "alerts:write", "cases:read"]

    alert = new_alert(client, admin).json()
    assert client.get(f"{API}/alerts/", headers=triage).status_code == 200
    assert client.patch(f"{API}/alerts/{alert['id']}/status", params={"status": "in_progress"}, headers=triage).status_code == 200
    cases = client.get(f"{API}/cases/", headers=triage)
    assert cases.status_code == 200
    case_id = alert.get("case_id") or client.get(f"{API}/alerts/{alert['id']}", headers=admin).json()["case_id"]
    refused = client.patch(f"{API}/cases/{case_id}", json={"status": "in_progress"}, headers=triage)
    assert refused.status_code == 403 and "cases:write" in refused.json()["detail"]
    assert client.get(f"{API}/events/", headers=triage).status_code == 403
    assert client.get(f"{API}/users/", headers=triage).status_code == 200  # colleagues, to assign alerts to
    assert client.post(f"{API}/roles", json={"name": "More", "permissions": []}, headers=triage).status_code == 403  # not an administrator

    # Changing the role changes what they can do at once.
    client.patch(f"{API}/roles/{role['id']}", json={"permissions": ["alerts:write", "cases:read", "events:read"]}, headers=admin)
    assert client.get(f"{API}/events/", headers=triage).status_code == 200


def test_roles_in_use_are_kept_and_roles_stay_in_their_organisation(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "rc")
    _, other_admin = sign_up(client, monkeypatch, "rd")
    role = client.post(f"{API}/roles", json={"name": "Watcher", "permissions": ["alerts:read"]}, headers=admin).json()
    _, account = person(client, admin, "custom", role["id"])
    assert client.get(f"{API}/roles", headers=admin).json()[0]["people"] == 1
    refused = client.delete(f"{API}/roles/{role['id']}", headers=admin)
    assert refused.status_code == 409 and "1 person has this role" in refused.json()["detail"]
    # Another organisation can neither see, use nor delete it.
    assert client.get(f"{API}/roles", headers=other_admin).json() == []
    stranger = client.post(f"{API}/users/", json={"username": f"x_{uuid.uuid4().hex[:6]}", "email": f"{uuid.uuid4().hex[:6]}@example.com",
                                                  "role": "custom", "custom_role_id": role["id"]}, headers=other_admin)
    assert stranger.status_code == 422
    assert client.delete(f"{API}/roles/{role['id']}", headers=other_admin).status_code == 404
    assert client.post(f"{API}/users/", json={"username": f"y_{uuid.uuid4().hex[:6]}", "email": f"{uuid.uuid4().hex[:6]}@example.com", "role": "custom"},
                       headers=admin).status_code == 422  # which role?

    moved = client.patch(f"{API}/users/{account['id']}", json={"role": "analyst"}, headers=admin).json()
    assert moved["role"] == "analyst" and moved["custom_role_id"] is None
    assert client.delete(f"{API}/roles/{role['id']}", headers=admin).status_code == 204


def test_live_updates_only_tell_a_role_what_it_may_see(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "re")
    role = client.post(f"{API}/roles", json={"name": "Cases only", "permissions": ["cases:read"]}, headers=admin).json()
    cases_only, _ = person(client, admin, "custom", role["id"])
    since = a_minute_ago()
    new_alert(client, admin)
    heard = [event for _, event, _ in read(client, cases_only, last_event_id=since)]
    assert "alert.created" not in heard and "case.created" in heard
