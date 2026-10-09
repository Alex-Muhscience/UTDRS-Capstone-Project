"""
System test: the API gateway and the core engine running as separate services.

An event posted to the gateway is analysed by the engine and comes back as an alert.
Run with scripts/system-test.sh, which starts both services against a MongoDB; set
GATEWAY_URL to point at an already running gateway instead.
"""
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

import httpx
import pytest

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8000")


@pytest.fixture(scope="module")
def api():
    with httpx.Client(base_url=f"{GATEWAY_URL}/api/v1", timeout=15) as client:
        suffix = uuid.uuid4().hex[:8]
        credentials = {"username": f"system_{suffix}", "password": secrets.token_urlsafe(16)}
        response = client.post(
            "/auth/register", json={**credentials, "email": f"system_{suffix}@example.com"}
        )
        assert response.status_code == 200, response.text
        token = client.post("/auth/login", data=credentials).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"
        yield client


def wait_for_analysis(api, event_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        analysis = api.get(f"/events/{event_id}").json().get("metadata", {}).get("analysis")
        if analysis:
            return analysis
        time.sleep(0.5)
    pytest.fail(f"Event {event_id} was not analysed within {timeout}s")


def test_ransomware_preparation_raises_an_alert(api):
    response = api.post(
        "/events/",
        json={
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process",
            "source": "endpoint_agent",
            "user_id": "jsmith",
            "description": "Shadow copies deleted",
            "raw_data": {"process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet"},
        },
    )
    assert response.status_code == 201, response.text
    event_id = response.json()["id"]

    analysis = wait_for_analysis(api, event_id)
    assert analysis["status"] == "threat", analysis

    alert = api.get(f"/alerts/{analysis['alert_id']}").json()
    assert alert["severity"] == "critical"
    assert alert["source"] == "core-engine"
    assert alert["event_ids"] == [event_id]
    assert "T1490" in alert["metadata"]["details"]["mitre_techniques"]


def test_routine_activity_raises_nothing(api):
    response = api.post(
        "/events/",
        json={
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process",
            "source": "endpoint_agent",
            "user_id": "jsmith",
            "description": "Editor opened",
            "raw_data": {"process_name": "notepad.exe", "command_line": "notepad.exe notes.txt"},
        },
    )
    assert response.status_code == 201, response.text
    assert wait_for_analysis(api, response.json()["id"])["status"] == "clean"


def test_a_signature_rule_raises_an_alert(api):
    response = api.post(
        "/events/",
        json={
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "dns",
            "source": "dns-resolver",
            "source_ip": "10.0.40.112",
            "description": "DNS query for a blocklisted domain",
            "raw_data": {"domain": "evil.net"},
        },
    )
    assert response.status_code == 201, response.text
    analysis = wait_for_analysis(api, response.json()["id"])
    assert analysis["status"] == "threat", analysis
    alert = api.get(f"/alerts/{analysis['alert_id']}").json()
    assert alert["title"] == "DNS Query to Suspicious Domain"
    assert alert["type"] == "signature"


def test_lists_only_show_the_gateways_own_records(api):
    # The engine stores events and alerts of its own; they must not leak into the
    # gateway's lists (which would also fail validation).
    for path in ("/events/", "/alerts/", "/events/recent/"):
        response = api.get(path, params={"limit": 500})
        assert response.status_code == 200, f"{path}: {response.text[:300]}"
        assert all("description" in row for row in response.json())
    assert all(alert["source"] == "core-engine" for alert in api.get("/alerts/").json())
