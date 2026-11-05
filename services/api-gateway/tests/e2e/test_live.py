"""Live updates: the dashboard hears of changes in its organisation as they happen."""
import json
import os
import secrets
import threading
import uuid
from datetime import timedelta

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from config import settings
from utils.time import utcnow

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def short_streams(monkeypatch):
    from api.routes import live as live_routes

    monkeypatch.setattr(live_routes, "STREAM_SECONDS", 1.5)
    monkeypatch.setattr(live_routes, "HEARTBEAT_SECONDS", 0.5)


def organisation(client, monkeypatch, role=None):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"lv_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"lv_{suffix}@example.com", "organisation": f"Org {suffix}"})
    auth = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    return auth, client.get(f"{API}/tenants/current", headers=auth).json()["id"]


def read(client, auth, last_event_id=None):
    """The stream's events until it ends, as (id, event, data)."""
    headers = {**auth, **({"Last-Event-ID": last_event_id} if last_event_id else {})}
    with client.stream("GET", f"{API}/live", headers=headers) as response:
        assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
        text = "".join(response.iter_text())
    found = []
    for block in text.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(":"))
        if "event" in fields:
            found.append((fields.get("id"), fields["event"], json.loads(fields.get("data", "{}"))))
    return found


def publish(client, tenant_id, event, data):
    from core.services import live

    client.portal.call(live.publish, event, data, tenant_id)


def a_minute_ago():
    return str(ObjectId.from_datetime(utcnow() - timedelta(minutes=1)))


def test_changes_reach_their_own_organisation_only(client, monkeypatch):
    a, a_id = organisation(client, monkeypatch)
    b, b_id = organisation(client, monkeypatch)
    alert = client.post(f"{API}/alerts/", json={"title": "Odd sign-in", "description": "x", "severity": "critical", "source": "x", "type": "x"}, headers=a).json()
    client.patch(f"{API}/alerts/{alert['id']}/status", params={"status": "in_progress"}, headers=a)
    publish(client, b_id, "case.created", {"id": "b-only"})

    events = read(client, a, last_event_id=a_minute_ago())
    names = [event for _, event, _ in events]
    assert names[0] == "ready"
    created = next(data for _, event, data in events if event == "alert.created")
    assert created["id"] == alert["id"] and created["title"] == "Odd sign-in" and created["severity"] == "critical"
    updated = next(data for _, event, data in events if event == "alert.updated")
    assert updated == {"id": alert["id"], "status": "in_progress"}
    assert all(data.get("id") != "b-only" for _, _, data in events)
    assert all(event_id for event_id, event, _ in events if event != "ready")  # each can be resumed from

    # Resuming from the last one gives nothing already seen.
    last = [event_id for event_id, event, _ in events if event_id][-1]
    assert [event for _, event, _ in read(client, a, last_event_id=last)] == ["ready"]
    assert "b-only" in str(read(client, b, last_event_id=a_minute_ago()))


def test_changes_arrive_while_connected(client, monkeypatch):
    a, a_id = organisation(client, monkeypatch)
    timer = threading.Timer(0.5, publish, (client, a_id, "action.approval_requested", {"id": "act-1"}))
    timer.start()
    try:
        events = read(client, a)
    finally:
        timer.join()
    assert ("action.approval_requested", {"id": "act-1"}) in [(event, data) for _, event, data in events]


def test_a_dashboard_that_missed_too_much_is_told_to_fetch_everything_again(client, monkeypatch):
    a, _ = organisation(client, monkeypatch)
    assert [event for _, event, _ in read(client, a, last_event_id="not-an-id")] == ["ready", "resync"]
    two_hours_ago = str(ObjectId.from_datetime(utcnow() - timedelta(hours=2)))
    assert [event for _, event, _ in read(client, a, last_event_id=two_hours_ago)] == ["ready", "resync"]


def test_the_stream_needs_a_signed_in_person(client):
    assert client.get(f"{API}/live").status_code == 401
