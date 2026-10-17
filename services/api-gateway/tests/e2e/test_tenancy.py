"""
Tenancy: one organisation can neither see nor change another's data, through any route.

Organisation A is the default one (its administrator is created at start-up); B is
created by registering in "organisation" mode.
"""
import json
import os
import secrets
import uuid
from datetime import datetime, timezone

import httpx
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


def sign_in(client, username, password):
    response = client.post(f"{API}/auth/login", data={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="module")
def a(client):
    return sign_in(client, os.environ["ADMIN_USERNAME"], os.environ["ADMIN_PASSWORD"])


@pytest.fixture(scope="module")
def b(client):
    """The administrator of a second organisation, made by registering."""
    original = settings.REGISTRATION_MODE
    settings.REGISTRATION_MODE = "organisation"
    try:
        username, password = f"founder_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
        response = client.post(
            f"{API}/auth/register",
            json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Beta Clinic"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["role"] == "admin"
    finally:
        settings.REGISTRATION_MODE = original
    return sign_in(client, username, password)


@pytest.fixture(scope="module")
def a_data(client, a):
    """One of everything in organisation A."""
    now = datetime.now(timezone.utc).isoformat()
    suffix = uuid.uuid4().hex[:6]
    asset = client.post(f"{API}/assets/", json={"name": f"shared-name-{suffix}", "asset_type": "server"}, headers=a).json()
    event = client.post(f"{API}/events/", json={"timestamp": now, "event_type": "network", "source": "fw", "description": "A's event", "asset_id": asset["id"]}, headers=a).json()
    alert = client.post(f"{API}/alerts/", json={"title": f"A's alert {suffix}", "description": "x", "severity": "high", "source": "x", "type": "x"}, headers=a).json()
    rule = client.post(f"{API}/detection/rules", json={"name": f"a-rule-{suffix}", "description": "x", "rule_type": "signature", "detection_source": "endpoint", "severity": "low", "status": "testing", "logic": "a == 1"}, headers=a).json()
    simulation = client.post(f"{API}/simulation/", json={"name": f"A's drill {suffix}", "description": "x", "scenario_type": "ransomware", "scope": "endpoint"}, headers=a)
    assert simulation.status_code == 201, simulation.text
    key = client.post(f"{API}/api-keys/", json={"name": f"a-key-{suffix}", "scopes": ["assets:read", "alerts:read"]}, headers=a).json()
    me = client.get(f"{API}/auth/me", headers=a).json()
    return {
        "asset": asset, "event": event, "alert": alert, "rule": rule, "key": key, "me": me,
        "simulation": simulation.json(),
    }


def ids(response):
    assert response.status_code == 200, response.text
    return {item["id"] for item in response.json()}


def test_registering_an_organisation_needs_its_name(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username = f"nameless_{uuid.uuid4().hex[:6]}"
    response = client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": secrets.token_urlsafe(16)})
    assert response.status_code == 422
    assert client.get(f"{API}/auth/config").json()["registration_mode"] == "organisation"


def test_each_person_sees_their_own_organisation(client, a, b):
    mine = client.get(f"{API}/tenants/current", headers=a).json()
    theirs = client.get(f"{API}/tenants/current", headers=b).json()
    assert mine["slug"] == settings.DEFAULT_TENANT_SLUG
    assert theirs["name"] == "Beta Clinic" and theirs["id"] != mine["id"]
    assert client.get(f"{API}/auth/me", headers=b).json()["tenant_id"] == theirs["id"]

    renamed = client.patch(f"{API}/tenants/current", json={"name": "Beta Health"}, headers=b).json()
    assert renamed["name"] == "Beta Health"
    assert client.get(f"{API}/tenants/current", headers=a).json()["name"] == mine["name"]


def test_lists_show_only_your_organisations_data(client, a, b, a_data):
    assert a_data["asset"]["id"] in ids(client.get(f"{API}/assets/", headers=a))
    assert a_data["asset"]["id"] not in ids(client.get(f"{API}/assets/", headers=b))
    assert a_data["event"]["id"] not in ids(client.get(f"{API}/events/", headers=b))
    assert a_data["alert"]["id"] not in ids(client.get(f"{API}/alerts/", headers=b))
    assert a_data["rule"]["id"] not in ids(client.get(f"{API}/detection/rules", headers=b))
    assert a_data["me"]["id"] not in ids(client.get(f"{API}/users/", headers=b))
    assert a_data["key"]["api_key"]["id"] not in ids(client.get(f"{API}/api-keys/", headers=b))
    assert a_data["simulation"]["id"] not in ids(client.get(f"{API}/simulation/", headers=b))
    assert client.get(f"{API}/simulation/{a_data['simulation']['id']}", headers=b).status_code == 404

    # Search, filters, recent lists and counts too.
    assert a_data["asset"]["id"] not in ids(client.get(f"{API}/assets/search/", params={"query": "shared-name"}, headers=b))
    assert a_data["alert"]["id"] not in ids(client.get(f"{API}/alerts/search/", params={"query": "A's alert"}, headers=b))
    assert a_data["event"]["id"] not in ids(client.get(f"{API}/events/", params={"asset_id": a_data["asset"]["id"]}, headers=b))
    assert a_data["event"]["id"] not in ids(client.get(f"{API}/events/recent/", headers=b))
    assert client.get(f"{API}/alerts/summary", headers=b).json()["total"] < client.get(f"{API}/alerts/summary", headers=a).json()["total"]


def test_another_organisations_items_cannot_be_read_or_changed(client, b, a_data):
    asset, alert, event, rule = a_data["asset"], a_data["alert"], a_data["event"], a_data["rule"]
    assert client.get(f"{API}/assets/{asset['id']}", headers=b).status_code == 404
    assert client.get(f"{API}/alerts/{alert['id']}", headers=b).status_code == 404
    assert client.get(f"{API}/events/{event['id']}", headers=b).status_code == 404
    assert client.get(f"{API}/detection/rules/{rule['id']}", headers=b).status_code == 404
    assert client.get(f"{API}/users/{a_data['me']['id']}", headers=b).status_code == 404

    assert client.put(f"{API}/assets/{asset['id']}", json={"name": "stolen"}, headers=b).status_code == 404
    assert client.patch(f"{API}/alerts/{alert['id']}/status", json={"status": "closed"}, headers=b).status_code in (404, 422)
    assert client.put(f"{API}/detection/rules/{rule['id']}", json={"severity": "critical"}, headers=b).status_code == 404
    assert client.patch(f"{API}/users/{a_data['me']['id']}", json={"active": False}, headers=b).status_code == 404
    assert client.delete(f"{API}/api-keys/{a_data['key']['api_key']['id']}", headers=b).status_code == 404

    # And nothing changed.
    assert client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {a_data['key']['key']}"}).status_code == 200


def test_alerts_are_assigned_only_within_an_organisation(client, a, b, a_data):
    b_me = client.get(f"{API}/auth/me", headers=b).json()
    response = client.patch(f"{API}/alerts/{a_data['alert']['id']}/assign", params={"assigned_to": b_me["id"]}, headers=a)
    assert response.status_code == 422


def test_names_are_unique_within_an_organisation_only(client, b, a_data):
    response = client.post(f"{API}/assets/", json={"name": a_data["asset"]["name"], "asset_type": "server"}, headers=b)
    assert response.status_code == 201, response.text
    assert response.json()["id"] != a_data["asset"]["id"]


def test_an_api_key_works_only_in_its_organisation(client, b, a_data):
    key = {"Authorization": f"Bearer {a_data['key']['key']}"}
    assert a_data["asset"]["id"] in ids(client.get(f"{API}/assets/", headers=key))
    b_asset = client.post(f"{API}/assets/", json={"name": f"b-only-{uuid.uuid4().hex[:6]}", "asset_type": "server"}, headers=b).json()
    assert client.get(f"{API}/assets/{b_asset['id']}", headers=key).status_code == 404


def test_each_organisation_has_its_own_audit_log(client, a, b, a_data):
    a_entries = client.get(f"{API}/audit-log/", params={"limit": 500}, headers=a).json()
    b_entries = client.get(f"{API}/audit-log/", params={"limit": 500}, headers=b).json()
    assert any(e["target"] and e["target"].get("id") == a_data["asset"]["id"] for e in a_entries)
    # Nothing A's people did is in B's log. (B's own failed attempts on A's items are,
    # naming only the ids B tried.)
    assert not any(e["actor"].get("id") == a_data["me"]["id"] for e in b_entries)
    assert all(e["outcome"] != "success" for e in b_entries if e["target"] and e["target"].get("id") == a_data["asset"]["id"])
    # B's chain is its own, numbered from 1, and intact.
    assert min(e["seq"] for e in b_entries) == 1
    assert client.get(f"{API}/audit-log/verify", headers=b).json()["ok"] is True


def test_rules_reach_the_engine_per_organisation(client, a, b, monkeypatch):
    from core.services import core_engine_client
    from core.services.core_engine_client import CoreEngineClient

    received = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        received[request.url.params["tenant_id"]] = [r["name"] for r in json.loads(request.content)["rules"]]
        return httpx.Response(200, json={"stored": 0, "removed": 0})

    monkeypatch.setattr(core_engine_client, "get_core_engine_client", lambda: CoreEngineClient("http://engine", transport=httpx.MockTransport(handler)))
    rule = {"description": "x", "rule_type": "signature", "detection_source": "endpoint", "severity": "low", "status": "enabled", "logic": "a == 1"}
    client.post(f"{API}/detection/rules", json={**rule, "name": "a-live"}, headers=a)
    client.post(f"{API}/detection/rules", json={**rule, "name": "b-live"}, headers=b)

    a_tenant = client.get(f"{API}/tenants/current", headers=a).json()["id"]
    b_tenant = client.get(f"{API}/tenants/current", headers=b).json()["id"]
    assert "a-live" in received[a_tenant] and "b-live" not in received[a_tenant]
    assert received[b_tenant] == ["b-live"]


def test_events_reach_the_engine_with_their_organisation(client, b, monkeypatch):
    from core.services import core_engine_client
    from core.services.core_engine_client import CoreEngineClient

    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/detections/process":
            sent.append(json.loads(request.content))
        return httpx.Response(200, content=b"null", headers={"content-type": "application/json"})

    monkeypatch.setattr(core_engine_client, "get_core_engine_client", lambda: CoreEngineClient("http://engine", transport=httpx.MockTransport(handler)))
    client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr", "description": "x"}, headers=b)
    assert sent and sent[-1]["tenant_id"] == client.get(f"{API}/tenants/current", headers=b).json()["id"]


def test_scoped_collections_fail_closed():
    from core.tenancy import ScopedCollection, TenantScopeError, tenant_context

    class Recorder:
        name = "assets"

        def find(self, filter=None, *args, **kwargs):
            return filter

        async def update_one(self, filter, update, *args, **kwargs):
            return filter, update

    collection = ScopedCollection(Recorder())
    with pytest.raises(TenantScopeError):
        collection.find({})  # no tenant set
    with tenant_context("t1"):
        assert collection.find({"name": "x"}) == {"name": "x", "tenant_id": "t1"}
        with pytest.raises(TenantScopeError):
            collection.find({"tenant_id": "t2"})
        with pytest.raises(TenantScopeError):
            collection.watch()  # anything not wrapped is refused

    import asyncio

    async def move():
        with tenant_context("t1"):
            await collection.update_one({}, {"$set": {"tenant_id": "t2"}})

    with pytest.raises(TenantScopeError):
        asyncio.run(move())
