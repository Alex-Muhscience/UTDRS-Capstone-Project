"""Managed service providers: working in the organisations they look after."""
import os
import uuid

import pytest
from bson import ObjectId

from tests.e2e.test_platform import PLATFORM, db, key, operator, sign_up  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
HEADER = "X-UTDRS-Organisation"


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from app import app

    with TestClient(app) as test_client:
        yield test_client


def org_id(client, auth):
    return client.get(f"{API}/tenants/current", headers=auth).json()["id"]


def colleague(client, admin, role):
    name = f"{role[:2]}_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": role}, headers=admin).json()
    token = client.post(f"{API}/auth/login", data={"username": name, "password": created["temporary_password"]}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, name


@pytest.fixture
def provider(client, monkeypatch):
    """A service provider managing one client: (msp admin, msp id, client admin, client id)."""
    msp_creds, msp_admin = sign_up(client, monkeypatch, "msp")
    _, client_admin = sign_up(client, monkeypatch, "cl")
    msp_id, client_id = org_id(client, msp_admin), org_id(client, client_admin)
    db(client, lambda d: d["tenants"].update_one({"_id": ObjectId(msp_id)}, {"$set": {"msp": True}}))
    db(client, lambda d: d["tenants"].update_one({"_id": ObjectId(client_id)}, {"$set": {"managed_by": msp_id}}))
    return msp_admin, msp_id, client_admin, client_id, msp_creds["username"]


def as_client(auth, client_id):
    return {**auth, HEADER: client_id}


def new_alert(client, auth, severity="high", title=None):
    return client.post(f"{API}/alerts/", json={"title": title or f"Alert {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity,
                                               "source": "x", "type": "x"}, headers=auth)


def test_a_provider_works_in_its_clients_and_they_see_who_did_what(client, provider):
    msp_admin, msp_id, client_admin, client_id, msp_username = provider
    overview = client.get(f"{API}/msp", headers=msp_admin).json()
    assert overview["msp"] and overview["role_in_clients"] == "admin" and [c["id"] for c in overview["clients"]] == [client_id]

    assert client.get(f"{API}/tenants/current", headers=as_client(msp_admin, client_id)).json()["id"] == client_id
    alert = new_alert(client, as_client(msp_admin, client_id), title="Made by the provider").json()
    assert alert["id"] in [a["id"] for a in client.get(f"{API}/alerts/", headers=client_admin).json()]  # in the client
    assert alert["id"] not in [a["id"] for a in client.get(f"{API}/alerts/", headers=msp_admin).json()]  # not the provider's own

    entries = client.get(f"{API}/audit-log/", headers=client_admin).json()
    rows = entries["items"] if isinstance(entries, dict) else entries
    made = next(e for e in rows if e["action"].startswith("alerts.") and e["actor"].get("name") == msp_username)
    assert made["actor"]["organisation"] and made["actor"]["msp_id"] == msp_id

    # Personal things stay the person's own: their profile is not the client's.
    me = client.get(f"{API}/auth/me", headers=as_client(msp_admin, client_id)).json()
    assert me["username"] == msp_username and me["tenant_id"] == msp_id

    # The client sees who manages it.
    assert client.get(f"{API}/tenants/current", headers=client_admin).json()["managed_by"] == msp_id


def test_roles_carry_over_into_clients(client, provider):
    msp_admin, _, _, client_id, _ = provider
    analyst, _ = colleague(client, msp_admin, "analyst")
    viewer, _ = colleague(client, msp_admin, "viewer")
    alert = new_alert(client, as_client(analyst, client_id))
    assert alert.status_code in (200, 201)
    assert client.patch(f"{API}/alerts/{alert.json()['id']}/status", params={"status": "in_progress"}, headers=as_client(analyst, client_id)).status_code == 200
    assert client.post(f"{API}/users/", json={"username": f"x_{uuid.uuid4().hex[:6]}", "email": f"{uuid.uuid4().hex[:6]}@example.com", "role": "analyst"},
                       headers=as_client(analyst, client_id)).status_code == 403  # not an administrator there
    assert client.get(f"{API}/alerts/", headers=as_client(viewer, client_id)).status_code == 200
    refused = new_alert(client, as_client(viewer, client_id))
    assert refused.status_code == 403 and "Read-only" in refused.json()["detail"]


def test_nobody_reaches_an_organisation_they_do_not_manage(client, provider, monkeypatch):
    msp_admin, _, client_admin, client_id, _ = provider
    _, stranger = sign_up(client, monkeypatch, "st")
    stranger_id = org_id(client, stranger)
    refused = client.get(f"{API}/alerts/", headers=as_client(msp_admin, stranger_id))
    assert refused.status_code == 403 and refused.headers["X-Organisation-Refused"] == "true"
    assert client.get(f"{API}/alerts/", headers=as_client(msp_admin, "not-an-id")).status_code == 403
    # Someone in an ordinary organisation, even a managed one, cannot switch at all.
    assert client.get(f"{API}/alerts/", headers=as_client(stranger, client_id)).status_code == 403
    assert client.get(f"{API}/alerts/", headers=as_client(client_admin, org_id(client, msp_admin))).status_code == 403
    assert client.get(f"{API}/msp", headers=stranger).json() == {"msp": False, "organisation_id": stranger_id,
                                                                 "organisation": client.get(f"{API}/tenants/current", headers=stranger).json()["name"],
                                                                 "role_in_clients": None, "clients": []}
    assert client.get(f"{API}/msp/alerts", headers=stranger).status_code == 403


def test_open_alerts_across_clients_most_severe_first(client, provider, monkeypatch):
    msp_admin, msp_id, client_admin, client_id, _ = provider
    _, second_admin = sign_up(client, monkeypatch, "c2")
    second_id = org_id(client, second_admin)
    db(client, lambda d: d["tenants"].update_one({"_id": ObjectId(second_id)}, {"$set": {"managed_by": msp_id}}))
    low = new_alert(client, client_admin, "low").json()
    critical = new_alert(client, second_admin, "critical").json()
    listed = client.get(f"{API}/msp/alerts", headers=msp_admin).json()
    ids = [a["id"] for a in listed]
    assert ids.index(critical["id"]) < ids.index(low["id"])
    assert {a["organisation_id"] for a in listed} == {client_id, second_id}
    clients = {c["id"]: c for c in client.get(f"{API}/msp", headers=msp_admin).json()["clients"]}
    assert clients[second_id]["urgent_alerts"] == 1 and clients[client_id]["urgent_alerts"] == 0


def test_a_provider_adds_clients_and_a_client_can_end_its_access(client, provider):
    msp_admin, msp_id, client_admin, client_id, _ = provider
    analyst, _ = colleague(client, msp_admin, "analyst")
    assert client.post(f"{API}/msp/clients", json={"name": "Not allowed"}, headers=analyst).status_code == 403
    suffix = uuid.uuid4().hex[:6]
    created = client.post(f"{API}/msp/clients", json={"name": f"New client {suffix}", "admin_username": f"na_{suffix}", "admin_email": f"na_{suffix}@example.com"},
                          headers=msp_admin)
    assert created.status_code == 201
    body = created.json()
    assert body["organisation"]["managed_by"] == msp_id and body["temporary_password"]
    new_id = body["organisation"]["id"]
    assert client.get(f"{API}/tenants/current", headers=as_client(msp_admin, new_id)).json()["name"] == f"New client {suffix}"

    # The provider cannot end its own access; the client's administrators can.
    assert client.delete(f"{API}/tenants/current/msp", headers=as_client(msp_admin, client_id)).status_code == 403
    released = client.delete(f"{API}/tenants/current/msp", headers=client_admin)
    assert released.status_code == 200 and released.json()["managed_by"] is None
    assert client.get(f"{API}/alerts/", headers=as_client(msp_admin, client_id)).status_code == 403
    assert client_id not in [c["id"] for c in client.get(f"{API}/msp", headers=msp_admin).json()["clients"]]


def test_a_client_that_requires_mfa_requires_it_of_its_provider_too(client, provider):
    msp_admin, _, _, client_id, _ = provider
    db(client, lambda d: d["tenants"].update_one({"_id": ObjectId(client_id)}, {"$set": {"security.require_mfa": True}}))
    refused = client.get(f"{API}/alerts/", headers=as_client(msp_admin, client_id))
    assert refused.status_code == 403 and "multi-factor" in refused.json()["detail"]


def test_platform_administrators_set_up_providers(client, monkeypatch, operator):  # noqa: F811
    auth, _ = operator
    _, msp_admin = sign_up(client, monkeypatch, "pm")
    _, other = sign_up(client, monkeypatch, "po")
    msp_id, other_id = org_id(client, msp_admin), org_id(client, other)
    assert client.patch(f"{PLATFORM}/organisations/{other_id}", json={"managed_by": msp_id}, headers=auth).status_code == 409  # not a provider yet
    assert client.patch(f"{PLATFORM}/organisations/{msp_id}", json={"msp": True}, headers=auth).json()["msp"] is True
    assigned = client.patch(f"{PLATFORM}/organisations/{other_id}", json={"managed_by": msp_id}, headers=auth).json()
    assert assigned["managed_by"] == msp_id and assigned["managed_by_name"]
    assert client.patch(f"{PLATFORM}/organisations/{other_id}", json={"msp": True}, headers=auth).status_code == 409  # managed ones cannot be providers
    assert client.patch(f"{PLATFORM}/organisations/{msp_id}", json={"msp": False}, headers=auth).status_code == 409  # it still has a client
    assert client.patch(f"{PLATFORM}/organisations/{other_id}", json={"managed_by": ""}, headers=auth).json()["managed_by"] is None
    assert client.patch(f"{PLATFORM}/organisations/{msp_id}", json={"msp": False}, headers=auth).json()["msp"] is False
