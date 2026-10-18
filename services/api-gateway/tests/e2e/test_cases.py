"""Cases: alerts about the same thing are grouped, and worked as one."""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

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


@pytest.fixture(scope="module")
def admin(client):
    response = client.post(f"{API}/auth/login", data={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def alert_about(client, auth, severity="medium", tags=(), title=None, **raw):
    """An event with these fields, and an alert raised from it."""
    event = client.post(
        f"{API}/events/",
        json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "authentication", "source": "vpn", "description": "x", "raw_data": raw},
        headers=auth,
    ).json()
    alert = client.post(
        f"{API}/alerts/",
        json={"title": title or f"Alert {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity, "source": "core-engine",
              "type": "signature", "tags": list(tags), "event_ids": [event["id"]]},
        headers=auth,
    ).json()
    return client.get(f"{API}/alerts/{alert['id']}", headers=auth).json()


def case_of(client, auth, alert):
    assert alert["case_id"], alert
    return client.get(f"{API}/cases/{alert['case_id']}", headers=auth).json()


def test_alerts_about_the_same_user_share_a_case(client, admin):
    user = f"jsmith-{uuid.uuid4().hex[:4]}"
    first = alert_about(client, admin, "medium", user=user, source_ip="203.0.113.7")
    second = alert_about(client, admin, "critical", user=user.upper())  # same person, other case of letters
    other = alert_about(client, admin, "low", user=f"other-{uuid.uuid4().hex[:4]}")

    assert first["case_id"] == second["case_id"] != other["case_id"]
    case = case_of(client, admin, second)
    assert case["alert_ids"] == [first["id"], second["id"]]
    assert {"type": "user", "value": user.lower(), "name": None} in case["entities"]
    assert {"type": "ip", "value": "203.0.113.7", "name": None} in case["entities"]
    # The case takes its most serious alert's priority, and is due sooner for it.
    assert case["priority"] == "critical"
    assert datetime.fromisoformat(case["due_at"]) <= datetime.fromisoformat(case["created_at"]) + timedelta(hours=1, seconds=1)
    assert [e["kind"] for e in case["timeline"]] == ["created", "alert_added", "alert_added"]


def test_a_shared_destination_does_not_group_alerts(client, admin):
    a = alert_about(client, admin, destination_ip="10.0.0.53", user=f"u1-{uuid.uuid4().hex[:4]}")
    b = alert_about(client, admin, destination_ip="10.0.0.53", user=f"u2-{uuid.uuid4().hex[:4]}")
    assert a["case_id"] != b["case_id"]


def test_an_old_case_is_not_reopened_by_a_new_alert(client, admin):
    host = f"ws-{uuid.uuid4().hex[:4]}"
    first = alert_about(client, admin, hostname=host)

    async def age():
        from bson import ObjectId
        from core.database.connection import get_database

        await get_database()["cases"].update_one({"_id": ObjectId(first["case_id"])}, {"$set": {"last_seen": datetime.now(timezone.utc) - timedelta(days=2)}})

    client.portal.call(age)
    later = alert_about(client, admin, hostname=host)
    assert later["case_id"] != first["case_id"]


def test_working_a_case(client, admin):
    user = f"ana-{uuid.uuid4().hex[:4]}"
    first = alert_about(client, admin, "high", user=user)
    second = alert_about(client, admin, "high", user=user)
    case_id = first["case_id"]
    me = client.get(f"{API}/auth/me", headers=admin).json()

    case = client.patch(f"{API}/cases/{case_id}", json={"status": "investigating", "owner_id": me["id"]}, headers=admin).json()
    assert (case["status"], case["owner_id"]) == ("investigating", me["id"])
    response = client.post(f"{API}/cases/{case_id}/notes", json={"text": "VPN logs show the same address on the 3rd."}, headers=admin)
    assert response.status_code == 201

    # Resolving the case resolves its alerts that are still open.
    assert client.patch(f"{API}/alerts/{second['id']}/status", params={"status": "false_positive"}, headers=admin).status_code == 200
    case = client.patch(f"{API}/cases/{case_id}", json={"status": "resolved"}, headers=admin).json()
    assert client.get(f"{API}/alerts/{first['id']}", headers=admin).json()["status"] == "resolved"
    assert client.get(f"{API}/alerts/{second['id']}", headers=admin).json()["status"] == "false_positive"

    kinds = [e["kind"] for e in case["timeline"]]
    # Marking an alert a false positive is a verdict, which the case records too.
    assert kinds[-6:] == ["status_changed", "owner_changed", "note", "feedback", "status_changed", "alerts_updated"]
    note = next(e for e in case["timeline"] if e["kind"] == "note")
    assert note["actor"]["name"] == me["username"] and note["text"].startswith("VPN logs")
    assert case["timeline"][-1]["text"] == "1 open alert set to resolved"
    assert case["breached"] is False  # a resolved case is never overdue

    assert client.get(f"{API}/cases/", params={"open_only": True}, headers=admin).json()
    assert case_id not in {c["id"] for c in client.get(f"{API}/cases/", params={"open_only": True, "limit": 500}, headers=admin).json()}


def test_an_owner_must_be_a_colleague(client, admin):
    case_id = alert_about(client, admin, user=f"x-{uuid.uuid4().hex[:4]}")["case_id"]
    response = client.patch(f"{API}/cases/{case_id}", json={"owner_id": "665f1c2ab1e2c3d4e5f6ffff"}, headers=admin)
    assert response.status_code == 422


def test_an_overdue_case_is_flagged(client, admin):
    case_id = alert_about(client, admin, "critical", user=f"late-{uuid.uuid4().hex[:4]}")["case_id"]

    async def overdue():
        from bson import ObjectId
        from core.database.connection import get_database

        await get_database()["cases"].update_one({"_id": ObjectId(case_id)}, {"$set": {"due_at": datetime.now(timezone.utc) - timedelta(minutes=5)}})

    client.portal.call(overdue)
    assert client.get(f"{API}/cases/{case_id}", headers=admin).json()["breached"] is True


def test_a_case_explains_itself(client, admin):
    host = f"fin-{uuid.uuid4().hex[:4]}"
    alert = alert_about(client, admin, "critical", tags=["ransomware", "T1490"], title="Shadow copies deleted", hostname=host)
    explanation = case_of(client, admin, alert)["explanation"]
    assert "Shadow copies deleted" in explanation["what_happened"] and host in explanation["what_happened"]
    assert "deleting backups" in explanation["why_it_matters"] and "within the hour" in explanation["why_it_matters"]
    assert explanation["next_steps"][0] == "Disconnect the affected computer from the network now"


def test_the_evidence_behind_a_case(client, admin):
    user = f"ev-{uuid.uuid4().hex[:4]}"
    first = alert_about(client, admin, user=user, source_ip="198.51.100.20")
    alert_about(client, admin, user=user)
    evidence = client.get(f"{API}/cases/{first['case_id']}/evidence", headers=admin).json()
    assert len(evidence["alerts"]) == 2 and len(evidence["events"]) == 2
    assert evidence["events"][0]["raw_data"]["source_ip"] == "198.51.100.20"
    assert "tenant_id" not in evidence["events"][0]


def test_cases_are_kept_within_an_organisation(client, admin, monkeypatch):
    case_id = alert_about(client, admin, user=f"t-{uuid.uuid4().hex[:4]}")["case_id"]
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"org_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}

    assert client.get(f"{API}/cases/{case_id}", headers=other).status_code == 404
    assert client.patch(f"{API}/cases/{case_id}", json={"status": "closed"}, headers=other).status_code == 404
    assert client.get(f"{API}/cases/", headers=other).json() == []


def test_api_keys_need_the_cases_scope(client, admin):
    key = client.post(f"{API}/api-keys/", json={"name": "alerts-only", "scopes": ["alerts:read"]}, headers=admin).json()["key"]
    assert client.get(f"{API}/cases/", headers={"Authorization": f"Bearer {key}"}).status_code == 403


def test_open_alerts_from_before_cases_are_put_in_cases(client, admin):
    user = f"old-{uuid.uuid4().hex[:4]}"
    first, second = alert_about(client, admin, user=user), alert_about(client, admin, user=user)
    closed = alert_about(client, admin, user=f"done-{uuid.uuid4().hex[:4]}")

    async def as_before_cases():
        from bson import ObjectId
        from core.database.connection import get_database
        from core.services import case_service, tenants
        from core.tenancy import set_tenant

        database = get_database()
        ids = [ObjectId(a["id"]) for a in (first, second, closed)]
        await database["alerts"].update_many({"_id": {"$in": ids}}, {"$unset": {"case_id": ""}})
        await database["alerts"].update_one({"_id": ids[2]}, {"$set": {"status": "resolved"}})
        await database["cases"].delete_many({"alert_ids": {"$in": [a["id"] for a in (first, second, closed)]}})
        set_tenant(await tenants.default_id())
        return await case_service.group_existing_alerts()

    assert client.portal.call(as_before_cases) >= 2
    a, b = (client.get(f"{API}/alerts/{x['id']}", headers=admin).json() for x in (first, second))
    assert a["case_id"] and a["case_id"] == b["case_id"]
    assert client.get(f"{API}/alerts/{closed['id']}", headers=admin).json()["case_id"] is None
    # The case is dated from its alerts, not from when it was made.
    case = client.get(f"{API}/cases/{a['case_id']}", headers=admin).json()
    assert case["first_seen"] == a["created_at"]


def test_a_case_names_its_devices(client, admin):
    asset = client.post(f"{API}/assets/", json={"name": f"fin-ws-{uuid.uuid4().hex[:4]}", "asset_type": "workstation"}, headers=admin).json()
    event = client.post(
        f"{API}/events/",
        json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr", "description": "x", "asset_id": asset["id"]},
        headers=admin,
    ).json()
    alert = client.post(
        f"{API}/alerts/",
        json={"title": "Odd process", "description": "x", "severity": "low", "source": "x", "type": "x", "event_ids": [event["id"]]},
        headers=admin,
    ).json()
    case = case_of(client, admin, client.get(f"{API}/alerts/{alert['id']}", headers=admin).json())
    assert {"type": "asset", "value": asset["id"], "name": asset["name"]} in case["entities"]
    assert asset["name"] in case["explanation"]["what_happened"] and asset["id"] not in case["explanation"]["what_happened"]
    listed = next(c for c in client.get(f"{API}/cases/", params={"limit": 500}, headers=admin).json() if c["id"] == case["id"])
    assert any(e.get("name") == asset["name"] for e in listed["entities"])
