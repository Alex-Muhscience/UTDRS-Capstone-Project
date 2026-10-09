"""
Event ingestion through to alerts, with the core engine replaced by a stand-in.

The real engine-to-gateway path is exercised by tests/system at the repository root,
which runs both services.
"""
import json
import os
import secrets
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from core.services import core_engine_client
from core.services.core_engine_client import CoreEngineClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

ENGINE_ALERT = {
    "id": "665f1c2ab1e2c3d4e5f60718",
    "title": "Potential Ransomware Activity: Recovery Inhibited",
    "description": "Shadow copies or backups are being deleted",
    "severity": "critical",
    "source": "endpoint_agent",
    "detection_type": "ml",
    "details": {"tags": ["ransomware", "inhibit-recovery"], "mitre_techniques": ["T1490"]},
    "status": "open",
    "event_ids": [],
    "created_at": "2026-01-01T00:00:00",
    "updated_at": "2026-01-01T00:00:00",
}


class FakeEngine:
    """Records what the gateway sends and answers like the core engine would."""

    def __init__(self, fail=False):
        self.fail = fail
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(503, json={"detail": "engine unavailable"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        self.requests.append(request)
        event = json.loads(request.content)
        if "delete shadows" in event["data"].get("command_line", ""):
            return httpx.Response(200, json=ENGINE_ALERT)
        # FastAPI serialises "no alert" (None) as the JSON literal null.
        return httpx.Response(200, content=b"null", headers={"content-type": "application/json"})


@pytest.fixture
def engine(monkeypatch):
    fake = FakeEngine()
    monkeypatch.setattr(
        core_engine_client,
        "get_core_engine_client",
        lambda: CoreEngineClient(
            "http://core-engine", token="internal-token", transport=httpx.MockTransport(fake.handler)
        ),
    )
    return fake


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"soc_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post("/api/v1/auth/register", json={**credentials, "email": f"soc_{suffix}@example.com"})
    token = client.post("/api/v1/auth/login", data=credentials).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def process_event(command_line):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process",
        "source": "endpoint_agent",
        "user_id": "jsmith",
        "description": "Process started",
        "raw_data": {"process_name": "vssadmin.exe", "command_line": command_line},
    }


def test_a_threat_becomes_an_alert_linked_to_the_event(client, auth, engine):
    response = client.post(
        "/api/v1/events/", json=process_event("vssadmin delete shadows /all /quiet"), headers=auth
    )
    assert response.status_code == 201, response.text
    event_id = response.json()["id"]

    # What the engine received: the detector fields under "data", with our token.
    sent = json.loads(engine.requests[0].content)
    assert engine.requests[0].headers["X-Internal-Token"] == "internal-token"
    assert sent["event_type"] == "process"
    assert sent["data"]["command_line"] == "vssadmin delete shadows /all /quiet"
    assert sent["data"]["user_id"] == "jsmith"
    assert sent["data"]["gateway_event_id"] == event_id

    analysis = client.get(f"/api/v1/events/{event_id}", headers=auth).json()["metadata"]["analysis"]
    assert analysis["status"] == "threat"

    alert = client.get(f"/api/v1/alerts/{analysis['alert_id']}", headers=auth).json()
    assert alert["severity"] == "critical"
    assert alert["source"] == "core-engine"
    assert alert["event_ids"] == [event_id]
    assert alert["metadata"]["details"]["mitre_techniques"] == ["T1490"]


def test_a_clean_event_raises_no_alert(client, auth, engine):
    response = client.post("/api/v1/events/", json=process_event("notepad.exe notes.txt"), headers=auth)
    assert response.status_code == 201, response.text
    event = client.get(f"/api/v1/events/{response.json()['id']}", headers=auth).json()
    assert event["metadata"]["analysis"]["status"] == "clean"
    assert "alert_id" not in event["metadata"]["analysis"]


def test_ingestion_survives_an_unavailable_engine(client, auth, engine):
    engine.fail = True
    response = client.post(
        "/api/v1/events/", json=process_event("vssadmin delete shadows /all /quiet"), headers=auth
    )
    assert response.status_code == 201, response.text
    event = client.get(f"/api/v1/events/{response.json()['id']}", headers=auth).json()
    assert event["metadata"]["analysis"]["status"] == "error"


def test_detection_status_reports_whether_the_engine_is_reachable(client, auth, engine):
    status = client.get("/api/v1/detection/", headers=auth).json()
    assert status["status"] == "active"
    assert status["core_engine"] == {"configured": True, "reachable": True}

    engine.fail = True
    status = client.get("/api/v1/detection/", headers=auth).json()
    assert status["status"] == "degraded"
    assert status["core_engine"] == {"configured": True, "reachable": False}
