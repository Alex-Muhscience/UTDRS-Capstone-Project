"""Roles, the team directory and account administration, against a real MongoDB."""
import os
import uuid

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def sign_in(client, username, password):
    response = client.post("/api/v1/auth/login", data={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="module")
def admin(client):
    return sign_in(client, os.environ["ADMIN_USERNAME"], os.environ["ADMIN_PASSWORD"])


def register(client):
    suffix = uuid.uuid4().hex[:8]
    password = uuid.uuid4().hex
    response = client.post(
        "/api/v1/auth/register",
        json={"username": f"analyst_{suffix}", "email": f"analyst_{suffix}@example.com", "password": password},
    )
    assert response.status_code == 200, response.text
    user = response.json()
    return user, sign_in(client, user["username"], password)


RULE = {
    "name": "rule",
    "description": "d",
    "rule_type": "signature",
    "detection_source": "network",
    "severity": "low",
    "logic": "x",
}


def test_the_configured_admin_is_created_at_startup(client, admin):
    me = client.get("/api/v1/auth/me", headers=admin).json()
    assert me["username"] == os.environ["ADMIN_USERNAME"]
    assert me["role"] == "admin"


def test_analysts_cannot_change_rules_or_simulations(client):
    _, analyst = register(client)
    assert client.post("/api/v1/detection/rules", json=RULE, headers=analyst).status_code == 403
    simulation = {"name": "s", "description": "d", "scenario_type": "ransomware", "scope": "endpoint"}
    assert client.post("/api/v1/simulation/", json=simulation, headers=analyst).status_code == 403
    # Reading stays open to everyone signed in.
    assert client.get("/api/v1/detection/rules", headers=analyst).status_code == 200


def test_admins_can_change_rules_and_simulations(client, admin):
    rule = {**RULE, "name": f"rule-{uuid.uuid4().hex[:6]}"}
    assert client.post("/api/v1/detection/rules", json=rule, headers=admin).status_code == 201

    simulation = {"name": "s", "description": "d", "scenario_type": "ransomware", "scope": "endpoint"}
    created = client.post("/api/v1/simulation/", json=simulation, headers=admin)
    assert created.status_code == 201, created.text
    started = client.post("/api/v1/simulation/start", params={"simulation_id": created.json()["id"]}, headers=admin)
    assert started.status_code == 200, started.text


def test_everyone_can_list_colleagues(client, admin):
    analyst_user, analyst = register(client)
    response = client.get("/api/v1/users/", headers=analyst)
    assert response.status_code == 200, response.text
    usernames = {user["username"] for user in response.json()}
    assert {analyst_user["username"], os.environ["ADMIN_USERNAME"]} <= usernames
    assert all("passwordHash" not in user for user in response.json())


def test_only_admins_administer_accounts(client, admin):
    target, analyst = register(client)
    assert client.patch(f"/api/v1/users/{target['id']}", json={"role": "admin"}, headers=analyst).status_code == 403
    assert client.post("/api/v1/users/", json={"username": "x" * 5, "email": "x@example.com"}, headers=analyst).status_code == 403

    response = client.patch(f"/api/v1/users/{target['id']}", json={"role": "admin"}, headers=admin)
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "admin"


def test_a_deactivated_account_is_signed_out_and_cannot_sign_in(client, admin):
    target, analyst = register(client)
    response = client.patch(f"/api/v1/users/{target['id']}", json={"active": False}, headers=admin)
    assert response.status_code == 200, response.text

    assert client.get("/api/v1/auth/me", headers=analyst).status_code == 401
    reset = client.post(f"/api/v1/users/{target['id']}/reset-password", headers=admin).json()
    login = client.post(
        "/api/v1/auth/login", data={"username": target["username"], "password": reset["temporary_password"]}
    )
    assert login.status_code == 403


def test_admins_create_accounts_and_reset_passwords(client, admin):
    suffix = uuid.uuid4().hex[:8]
    response = client.post(
        "/api/v1/users/",
        json={"username": f"new_{suffix}", "email": f"new_{suffix}@example.com", "role": "analyst"},
        headers=admin,
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["user"]["role"] == "analyst"
    sign_in(client, f"new_{suffix}", created["temporary_password"])

    reset = client.post(f"/api/v1/users/{created['user']['id']}/reset-password", headers=admin).json()
    assert reset["temporary_password"] != created["temporary_password"]
    sign_in(client, f"new_{suffix}", reset["temporary_password"])


def test_admins_cannot_lock_themselves_out(client, admin):
    me = client.get("/api/v1/auth/me", headers=admin).json()
    response = client.patch(f"/api/v1/users/{me['id']}", json={"active": False}, headers=admin)
    assert response.status_code == 400
    response = client.patch(f"/api/v1/users/{me['id']}", json={"role": "analyst"}, headers=admin)
    assert response.status_code == 400


def test_registration_can_be_closed(client, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", False)
    assert client.get("/api/v1/auth/config").json() == {"allow_registration": False}
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "closed_reg", "email": "closed@example.com", "password": uuid.uuid4().hex},
    )
    assert response.status_code == 403


def test_the_admin_setting_promotes_and_reactivates_an_existing_account(client, admin, monkeypatch):
    from config import settings
    from core.services.bootstrap import ensure_admin

    target, _ = register(client)
    client.patch(f"/api/v1/users/{target['id']}", json={"active": False}, headers=admin)

    monkeypatch.setattr(settings, "ADMIN_USERNAME", target["username"])
    client.portal.call(ensure_admin)

    user = client.get(f"/api/v1/users/{target['id']}", headers=admin).json()
    assert user["role"] == "admin" and user["active"] is True
