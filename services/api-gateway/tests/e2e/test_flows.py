"""
End-to-end flows against a real MongoDB: no repository or service mocks.

Run with MONGODB_URI pointing at a disposable database server; each run uses
its own database (DB_NAME is set by tests/conftest.py) which is dropped afterwards.
"""
import os
import secrets
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

# Generated per run, so no password is committed.
PASSWORD = secrets.token_urlsafe(16)


def _id(body):
    # Documents are exposed with "id", never MongoDB's "_id".
    assert "_id" not in body
    return body["id"]


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"analyst_{suffix}", "password": PASSWORD}
    response = client.post(
        "/api/v1/auth/register",
        json={**credentials, "email": f"analyst_{suffix}@example.com", "role": "analyst"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["username"] == credentials["username"]

    response = client.post("/api/v1/auth/login", data=credentials)
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_requests_without_a_token_are_rejected(client):
    assert client.get("/api/v1/alerts/").status_code == 401


def test_current_user(client, auth):
    response = client.get("/api/v1/auth/me", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["username"].startswith("analyst_")


def test_event_lifecycle(client, auth):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "authentication",
        "source": "vpn-gateway",
        "source_ip": "203.0.113.7",
        "action": "deny",
        "description": "Failed VPN login",
        "raw_data": {"attempts": 12},
    }
    response = client.post("/api/v1/events/", json=event, headers=auth)
    assert response.status_code == 201, response.text
    event_id = _id(response.json())

    response = client.get(f"/api/v1/events/{event_id}", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["source_ip"] == "203.0.113.7"

    response = client.get("/api/v1/events/", headers=auth)
    assert response.status_code == 200, response.text
    assert event_id in [_id(item) for item in response.json()]


def test_alert_lifecycle(client, auth):
    alert = {
        "title": "Brute force on VPN",
        "description": "12 failed logins in 60 seconds",
        "severity": "high",
        "source": "SIEM",
        "type": "intrusion",
        "tags": ["brute-force"],
    }
    response = client.post("/api/v1/alerts/", json=alert, headers=auth)
    assert response.status_code == 201, response.text
    alert_id = _id(response.json())

    response = client.get(f"/api/v1/alerts/{alert_id}", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "open"

    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status", params={"status": "in_progress"}, headers=auth
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "in_progress"


def _create_alert(client, auth, **fields):
    alert = {"title": "Test alert", "description": "-", "severity": "low", "source": "SIEM", "type": "intrusion"}
    response = client.post("/api/v1/alerts/", json={**alert, **fields}, headers=auth)
    assert response.status_code == 201, response.text
    return _id(response.json())


def test_alerts_are_listed_newest_first_and_filters_combine(client, auth):
    tag = uuid.uuid4().hex[:8]
    first = _create_alert(client, auth, severity="critical", tags=[tag])
    second = _create_alert(client, auth, severity="critical", tags=[tag])
    _create_alert(client, auth, severity="low", tags=[tag])
    client.patch(f"/api/v1/alerts/{first}/status", params={"status": "resolved"}, headers=auth)

    response = client.get(
        "/api/v1/alerts/", params={"status": "open", "severity": "critical"}, headers=auth
    )
    assert response.status_code == 200, response.text
    alerts = response.json()
    assert all(a["status"] == "open" and a["severity"] == "critical" for a in alerts)
    ids = [a["id"] for a in alerts]
    assert second in ids and first not in ids

    newest = client.get("/api/v1/alerts/", params={"limit": 3}, headers=auth).json()
    assert [a["tags"] for a in newest] == [[tag]] * 3
    assert newest[1]["id"] == second


def test_alert_summary_counts_by_status_and_open_severity(client, auth):
    before = client.get("/api/v1/alerts/summary", headers=auth).json()
    _create_alert(client, auth, severity="high")
    resolved = _create_alert(client, auth, severity="high")
    client.patch(f"/api/v1/alerts/{resolved}/status", params={"status": "resolved"}, headers=auth)

    after = client.get("/api/v1/alerts/summary", headers=auth).json()
    assert after["total"] == before["total"] + 2
    assert after["by_status"].get("resolved", 0) == before["by_status"].get("resolved", 0) + 1
    assert after["open_by_severity"]["high"] == before["open_by_severity"].get("high", 0) + 1


def test_alert_status_errors_are_client_errors(client, auth):
    alert_id = _create_alert(client, auth)
    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status", params={"status": "bogus"}, headers=auth
    )
    assert response.status_code == 400
    response = client.patch(
        "/api/v1/alerts/000000000000000000000000/status", params={"status": "closed"}, headers=auth
    )
    assert response.status_code == 404


def test_asset_lifecycle(client, auth):
    asset = {"name": f"web-{uuid.uuid4().hex[:6]}", "asset_type": "server", "ip_address": "10.0.0.5"}
    response = client.post("/api/v1/assets/", json=asset, headers=auth)
    assert response.status_code == 201, response.text
    asset_id = _id(response.json())

    response = client.get(f"/api/v1/assets/{asset_id}", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["ip_address"] == "10.0.0.5"


def test_detection_rule_lifecycle(client, auth):
    rule = {
        "name": f"vpn-bruteforce-{uuid.uuid4().hex[:6]}",
        "description": "Many failed VPN logins from one address",
        "rule_type": "signature",
        "detection_source": "network",
        "severity": "high",
        "logic": "event_type == 'authentication' and action == 'deny'",
    }
    response = client.post("/api/v1/detection/rules", json=rule, headers=auth)
    assert response.status_code == 201, response.text
    rule_id = _id(response.json())

    response = client.get(f"/api/v1/detection/rules/{rule_id}", headers=auth)
    assert response.status_code == 200, response.text
    assert response.json()["severity"] == "high"

    response = client.patch(
        f"/api/v1/detection/rules/{rule_id}/status", params={"status": "testing"}, headers=auth
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "testing"

    response = client.patch(
        f"/api/v1/detection/rules/{rule_id}/status", params={"status": "bogus"}, headers=auth
    )
    assert response.status_code == 400


def test_detection_status_without_a_core_engine(client, auth, monkeypatch):
    from core.services import core_engine_client

    monkeypatch.setattr(core_engine_client, "get_core_engine_client", lambda: None)
    status = client.get("/api/v1/detection/", headers=auth).json()
    assert status["status"] == "standalone"
    assert status["core_engine"] == {"configured": False, "reachable": False}
    assert status["total_rules"] >= status["enabled_rules"] + status["testing_rules"]


def test_registration_cannot_choose_a_role(client):
    suffix = uuid.uuid4().hex[:8]
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": f"mallory_{suffix}",
            "email": f"mallory_{suffix}@example.com",
            "password": PASSWORD,
            "role": "admin",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "analyst"


def test_users_cannot_change_their_own_role(client, auth):
    response = client.put(
        "/api/v1/auth/me", json={"role": "admin", "active": False, "firstName": "Ann"}, headers=auth
    )
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "analyst"
    assert response.json()["active"] is True
    assert response.json()["firstName"] == "Ann"


@pytest.mark.parametrize("password", ["short", "x" * 73])
def test_password_length_is_enforced(client, password):
    suffix = uuid.uuid4().hex[:8]
    response = client.post(
        "/api/v1/auth/register",
        json={"username": f"u_{suffix}", "email": f"u_{suffix}@example.com", "password": password},
    )
    assert response.status_code == 422
