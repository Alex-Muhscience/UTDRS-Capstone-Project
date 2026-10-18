"""Data retention: old data goes, open work stays."""
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
def org(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"ret_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def raise_alert(client, auth, **raw):
    event = client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr",
                                                 "description": "x", "raw_data": raw}, headers=auth).json()
    alert = client.post(f"{API}/alerts/", json={"title": f"A {uuid.uuid4().hex[:4]}", "description": "x", "severity": "low", "source": "x",
                                                 "type": "x", "event_ids": [event["id"]]}, headers=auth).json()
    return event, client.get(f"{API}/alerts/{alert['id']}", headers=auth).json()


def age(client, collection, ids, days, field):
    async def update():
        from core.database.connection import get_database

        await get_database()[collection].update_many(
            {"_id": {"$in": [ObjectId(i) for i in ids]}}, {"$set": {field: datetime.now(timezone.utc) - timedelta(days=days)}}
        )

    client.portal.call(update)


def exists(client, collection, item_id):
    async def find():
        from core.database.connection import get_database

        return await get_database()[collection].find_one({"_id": ObjectId(item_id)}) is not None

    return client.portal.call(find)


def test_settings_have_defaults_and_a_maximum(client, org):
    body = client.get(f"{API}/retention/", headers=org).json()
    assert body["days"] == body["defaults"] == {"events": 90, "alerts": 365, "cases": 365, "actions": 365, "notifications": 90, "labels": 730}
    assert body["max_days"] == 730 and body["last_run"] is None
    assert client.patch(f"{API}/retention/", json={"events": 30}, headers=org).json()["days"]["events"] == 30
    response = client.patch(f"{API}/retention/", json={"events": 5000}, headers=org)
    assert response.status_code == 422 and "At most 730 days" in response.json()["detail"]
    assert client.patch(f"{API}/retention/", json={"events": 0}, headers=org).status_code == 422


def test_old_data_goes_and_open_work_stays(client, org):
    client.patch(f"{API}/retention/", json={"events": 30, "alerts": 60, "cases": 60}, headers=org)
    stale_event = client.post(f"{API}/events/", json={"timestamp": "2026-01-01T00:00:00Z", "event_type": "process", "source": "edr", "description": "x"}, headers=org).json()
    fresh_event = client.post(f"{API}/events/", json={"timestamp": "2026-01-01T00:00:00Z", "event_type": "process", "source": "edr", "description": "x"}, headers=org).json()
    # An old alert still open, in an open case: its event is evidence, and stays.
    open_event, open_alert = raise_alert(client, org, user=f"u-{uuid.uuid4().hex[:4]}")
    # An old alert closed, in a closed case: all of it goes.
    done_event, done_alert = raise_alert(client, org, user=f"d-{uuid.uuid4().hex[:4]}")
    client.patch(f"{API}/cases/{done_alert['case_id']}", json={"status": "closed"}, headers=org)

    age(client, "events", [stale_event["id"], open_event["id"], done_event["id"]], 40, "created_at")
    age(client, "alerts", [open_alert["id"], done_alert["id"]], 70, "updated_at")
    age(client, "cases", [open_alert["case_id"], done_alert["case_id"]], 70, "updated_at")

    deleted = client.post(f"{API}/retention/run", headers=org).json()
    assert deleted["events"] == 2 and deleted["alerts"] == 1 and deleted["cases"] == 1

    assert not exists(client, "events", stale_event["id"]) and not exists(client, "events", done_event["id"])
    assert exists(client, "events", fresh_event["id"]) and exists(client, "events", open_event["id"])
    assert exists(client, "alerts", open_alert["id"]) and exists(client, "cases", open_alert["case_id"])
    assert not exists(client, "alerts", done_alert["id"]) and not exists(client, "cases", done_alert["case_id"])

    last = client.get(f"{API}/retention/", headers=org).json()["last_run"]
    assert last["deleted"] == deleted and last["at"]


def test_a_closed_alert_in_an_open_case_stays(client, org):
    client.patch(f"{API}/retention/", json={"alerts": 30}, headers=org)
    user = f"k-{uuid.uuid4().hex[:4]}"
    _, first = raise_alert(client, org, user=user)
    raise_alert(client, org, user=user)  # same case, still open
    client.patch(f"{API}/alerts/{first['id']}/status", params={"status": "resolved"}, headers=org)
    age(client, "alerts", [first["id"]], 40, "updated_at")
    client.post(f"{API}/retention/run", headers=org)
    assert exists(client, "alerts", first["id"])


def test_actions_waiting_for_a_decision_stay(client, org):
    client.patch(f"{API}/retention/", json={"actions": 30}, headers=org)
    _, alert = raise_alert(client, org, user=f"p-{uuid.uuid4().hex[:4]}")
    key = client.post(f"{API}/api-keys/", json={"name": "k", "scopes": ["response:write", "response:read"]}, headers=org).json()["key"]
    waiting = client.post(f"{API}/response/actions", json={"action": "utdrs.escalate_case", "target": {"type": "case", "value": alert["case_id"]}, "params": {"priority": "high"}},
                          headers={"Authorization": f"Bearer {key}"}).json()
    done = client.post(f"{API}/response/actions", json={"action": "utdrs.escalate_case", "target": {"type": "case", "value": alert["case_id"]}, "params": {"priority": "high"}}, headers=org).json()
    age(client, "actions", [waiting["id"], done["id"]], 40, "created_at")
    assert client.post(f"{API}/retention/run", headers=org).json()["actions"] == 1
    assert exists(client, "actions", waiting["id"]) and not exists(client, "actions", done["id"])


def test_each_organisation_keeps_its_own_data_its_own_time(client, org, monkeypatch):
    mine = client.post(f"{API}/events/", json={"timestamp": "2026-01-01T00:00:00Z", "event_type": "process", "source": "edr", "description": "x"}, headers=org).json()
    age(client, "events", [mine["id"]], 40, "created_at")
    username, password = f"ret_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}
    client.patch(f"{API}/retention/", json={"events": 1}, headers=other)
    client.post(f"{API}/retention/run", headers=other)
    assert exists(client, "events", mine["id"])  # the other organisation's settings and run never touch it
    assert client.get(f"{API}/retention/", headers=org).json()["days"]["events"] == 90


def test_only_administrators(client, org):
    username = f"ana_{uuid.uuid4().hex[:6]}"
    temporary = client.post(f"{API}/users/", json={"username": username, "email": f"{username}@example.com", "role": "analyst"}, headers=org).json()["temporary_password"]
    analyst = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': temporary}).json()['access_token']}"}
    assert client.get(f"{API}/retention/", headers=analyst).status_code == 403
    assert client.post(f"{API}/retention/run", headers=analyst).status_code == 403
