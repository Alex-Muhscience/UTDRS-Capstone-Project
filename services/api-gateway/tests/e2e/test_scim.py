"""SCIM 2.0: an identity provider managing an organisation's accounts, as Entra ID and Okta do."""
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
SCIM = f"{API}/scim/v2"
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def organisation(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"sc_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"sc_{suffix}@example.com", "organisation": f"Org {suffix}"})
    admin = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    token = client.post(f"{API}/tenants/current/scim/token", headers=admin).json()["token"]
    return admin, {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}


@pytest.fixture
def org(client, monkeypatch):
    return organisation(client, monkeypatch)


def person(suffix=None, **extra):
    suffix = suffix or uuid.uuid4().hex[:8]
    return {"schemas": [USER], "userName": f"p{suffix}@example.com", "externalId": f"ext-{suffix}", "active": True,
            "name": {"givenName": "Pat", "familyName": "Lee"}, "emails": [{"value": f"p{suffix}@example.com", "type": "work", "primary": True}], **extra}


def test_the_token_is_needed(client, org):
    assert client.get(f"{SCIM}/Users").status_code == 401
    refused = client.get(f"{SCIM}/Users", headers={"Authorization": "Bearer utdrs_scim_wrong"})
    assert refused.status_code == 401 and refused.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_an_identity_provider_creates_finds_and_updates_people(client, org):
    admin, idp = org
    created = client.post(f"{SCIM}/Users", json=person(), headers=idp)
    assert created.status_code == 201, created.text
    user = created.json()
    assert created.headers["content-type"].startswith("application/scim+json") and created.headers["location"].endswith(user["id"])
    assert user["active"] is True and user["name"] == {"givenName": "Pat", "familyName": "Lee"} and user["externalId"].startswith("ext-")

    # Entra ID looks people up by userName before creating them.
    found = client.get(f"{SCIM}/Users", params={"filter": f'userName eq "{user["userName"]}"'}, headers=idp).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == user["id"]
    assert client.get(f"{SCIM}/Users", params={"filter": 'userName eq "nobody@example.com"'}, headers=idp).json()["totalResults"] == 0
    assert client.post(f"{SCIM}/Users", json=person(user["userName"][1:9]), headers=idp).status_code == 409

    # Entra ID's PATCH: replace with paths, and active as a string.
    patched = client.patch(f"{SCIM}/Users/{user['id']}", json={"schemas": [PATCH], "Operations": [
        {"op": "Replace", "path": "name.familyName", "value": "Lee-Smith"},
        {"op": "Replace", "path": "active", "value": "False"},
    ]}, headers=idp).json()
    assert patched["name"]["familyName"] == "Lee-Smith" and patched["active"] is False

    # Okta's PATCH: replace with a partial resource and no path.
    again = client.patch(f"{SCIM}/Users/{user['id']}", json={"schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": True}}]}, headers=idp)
    assert again.json()["active"] is True

    # PUT replaces.
    replaced = client.put(f"{SCIM}/Users/{user['id']}", json={**person(), "userName": user["userName"], "emails": user["emails"], "name": {"givenName": "Patricia", "familyName": "Lee"}}, headers=idp).json()
    assert replaced["name"]["givenName"] == "Patricia"

    # UTDRS's own view: an analyst, with a confirmed address.
    listed = next(u for u in client.get(f"{API}/users/", headers=admin).json() if u["id"] == user["id"])
    assert listed["role"] == "analyst" and listed["email_verified"] is True and listed["firstName"] == "Patricia"


def test_deactivating_someone_signs_them_out(client, org):
    admin, idp = org
    created = client.post(f"{SCIM}/Users", json=person(), headers=idp).json()
    # Give them a password to sign in with, as an administrator could.
    password = client.post(f"{API}/users/{created['id']}/reset-password", headers=admin).json()["temporary_password"]
    session = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': created['userName'], 'password': password}).json()['access_token']}"}
    assert client.get(f"{API}/auth/me", headers=session).status_code == 200

    assert client.delete(f"{SCIM}/Users/{created['id']}", headers=idp).status_code == 204
    assert client.get(f"{API}/auth/me", headers=session).status_code == 401
    assert client.get(f"{SCIM}/Users/{created['id']}", headers=idp).json()["active"] is False


def test_the_last_administrator_cannot_be_deactivated(client, org):
    admin, idp = org
    me = client.get(f"{API}/auth/me", headers=admin).json()
    refused = client.patch(f"{SCIM}/Users/{me['id']}", json={"schemas": [PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]}, headers=idp)
    assert refused.status_code == 400 and refused.json()["scimType"] == "mutability"
    assert client.get(f"{API}/auth/me", headers=admin).status_code == 200


def test_people_stay_in_their_organisation(client, org, monkeypatch):
    _, idp = org
    created = client.post(f"{SCIM}/Users", json=person(), headers=idp).json()
    _, other = organisation(client, monkeypatch)
    assert client.get(f"{SCIM}/Users/{created['id']}", headers=other).status_code == 404
    assert client.get(f"{SCIM}/Users", params={"filter": f'userName eq "{created["userName"]}"'}, headers=other).json()["totalResults"] == 0
    assert client.delete(f"{SCIM}/Users/{created['id']}", headers=other).status_code == 404


def test_a_revoked_token_stops_working_and_discovery_answers(client, org):
    admin, idp = org
    config = client.get(f"{SCIM}/ServiceProviderConfig", headers=idp).json()
    assert config["patch"]["supported"] is True and config["bulk"]["supported"] is False
    assert client.get(f"{SCIM}/Groups", headers=idp).json()["totalResults"] == 0
    status = client.get(f"{API}/tenants/current/scim", headers=admin).json()
    assert status["enabled"] and status["last_used_at"]
    assert client.delete(f"{API}/tenants/current/scim/token", headers=admin).status_code == 204
    assert client.get(f"{SCIM}/Users", headers=idp).status_code == 401
