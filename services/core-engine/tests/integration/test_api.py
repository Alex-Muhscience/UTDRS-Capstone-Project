"""The detection API end to end: event in, alert out, stored in MongoDB."""
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from tests.conftest import requires_mongodb

pytestmark = requires_mongodb

RANSOMWARE_PRECURSOR = {
    "source": "endpoint_agent",
    "event_type": "process",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "data": {
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
        "user_id": "jsmith",
    },
}


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client
        # Leave no test data behind.
        from pymongo import MongoClient
        import os

        with MongoClient(os.environ["MONGODB_URI"]) as sync_client:
            sync_client.drop_database(os.environ["DB_NAME"])


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/health/db").json()["database"] == "connected"


def test_a_threat_produces_a_stored_alert(client):
    response = client.post("/detections/process", json=RANSOMWARE_PRECURSOR)
    assert response.status_code == 200, response.text
    alert = response.json()
    assert alert is not None
    assert alert["severity"] == "critical"
    assert "_id" not in alert and alert["id"]

    response = client.get(f"/detections/alerts/{alert['id']}")
    assert response.status_code == 200, response.text
    assert response.json()["title"] == alert["title"]


def test_a_benign_event_produces_no_alert(client):
    benign = {
        "source": "endpoint_agent",
        "event_type": "process",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"process_name": "notepad.exe", "command_line": "notepad.exe report.txt", "user_id": "jsmith"},
    }
    response = client.post("/detections/process", json=benign)
    assert response.status_code == 200, response.text
    assert response.json() is None


def test_internal_token_is_enforced_when_configured(client, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "INTERNAL_API_TOKEN", "s3cret-token")
    assert client.get("/detections/alerts").status_code == 401
    assert client.get("/detections/alerts", headers={"X-Internal-Token": "wrong"}).status_code == 401
    assert client.get("/detections/alerts", headers={"X-Internal-Token": "s3cret-token"}).status_code == 200
    # Health stays open for load balancers and the gateway's checks.
    assert client.get("/health").status_code == 200
