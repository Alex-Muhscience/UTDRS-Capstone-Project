"""
Device scans from the scanner: a scan keeps its asset up to date, and a new device or
a changed inventory raises an event.
"""
import os
import secrets
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

TOKEN = "scanner-pipeline-token"
INTERNAL = {"X-Internal-Token": TOKEN}


@pytest.fixture(autouse=True)
def internal_token(monkeypatch):
    monkeypatch.setattr(settings, "INTERNAL_API_TOKEN", TOKEN)
    # No core engine: these tests are about assets and events, not detection.
    monkeypatch.setattr(settings, "CORE_ENGINE_URL", None)


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"scan_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post("/api/v1/auth/register", json={**credentials, "email": f"scan_{suffix}@example.com"})
    token = client.post("/api/v1/auth/login", data=credentials).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def scan(hostname, **overrides):
    return {
        "hostname": hostname,
        "os": "Linux",
        "os_version": "6.8.0",
        "cpu_cores": 4,
        "memory_kb": 8_000_000,
        "interfaces": [
            {"name": "lo", "ip_address": "127.0.0.1"},
            {"name": "eth0", "ip_address": "10.0.0.7", "mac_address": "02:42:0a:00:00:07"},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reported_from": "10.0.0.7",
        "scan_id": uuid.uuid4().hex,
        **overrides,
    }


def test_the_first_scan_of_a_device_creates_an_asset_and_an_event(client, auth):
    hostname = f"host-{uuid.uuid4().hex[:8]}"
    response = client.post("/api/v1/scans/", json=scan(hostname), headers=INTERNAL)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["new_device"] is True
    assert result["changes"] == []

    asset = client.get(f"/api/v1/assets/{result['asset_id']}", headers=auth).json()
    assert asset["name"] == hostname
    assert asset["os"] == "Linux 6.8.0"
    # The address shown is the first interface that is not loopback.
    assert asset["ip_address"] == "10.0.0.7"
    assert asset["mac_address"] == "02:42:0a:00:00:07"
    assert asset["tags"] == ["scanner"]
    assert asset["last_seen"]

    event = client.get(f"/api/v1/events/{result['event_id']}", headers=auth).json()
    assert event["event_type"] == "asset_scan"
    assert event["source"] == "device-scanner"
    assert event["asset_id"] == result["asset_id"]
    assert event["description"] == f"New device discovered: {hostname}"
    assert event["raw_data"]["new_device"] is True


def test_an_unchanged_scan_only_refreshes_the_asset(client, auth):
    hostname = f"host-{uuid.uuid4().hex[:8]}"
    first = client.post("/api/v1/scans/", json=scan(hostname), headers=INTERNAL).json()

    again = client.post("/api/v1/scans/", json=scan(hostname), headers=INTERNAL)
    assert again.status_code == 200, again.text
    result = again.json()
    assert result == {
        "asset_id": first["asset_id"],
        "new_device": False,
        "changes": [],
        "event_id": None,
    }

    events = client.get(f"/api/v1/events/?asset_id={first['asset_id']}", headers=auth).json()
    assert [event["id"] for event in events] == [first["event_id"]]


def test_a_changed_inventory_raises_an_event_and_keeps_the_analysts_edits(client, auth):
    hostname = f"host-{uuid.uuid4().hex[:8]}"
    first = client.post("/api/v1/scans/", json=scan(hostname), headers=INTERNAL).json()
    edited = client.put(
        f"/api/v1/assets/{first['asset_id']}",
        json={"asset_type": "server", "criticality": "critical", "owner": "Platform team"},
        headers=auth,
    )
    assert edited.status_code == 200, edited.text

    changed = scan(
        hostname,
        os_version="6.9.1",
        interfaces=[{"name": "eth0", "ip_address": "10.0.0.99", "mac_address": "02:42:0a:00:00:63"}],
    )
    result = client.post("/api/v1/scans/", json=changed, headers=INTERNAL).json()
    assert result["new_device"] is False
    assert result["changes"] == ["os", "interfaces"]

    event = client.get(f"/api/v1/events/{result['event_id']}", headers=auth).json()
    assert event["description"] == f"Device inventory changed on {hostname}: os, interfaces"
    assert event["source_ip"] == "10.0.0.99"

    asset = client.get(f"/api/v1/assets/{first['asset_id']}", headers=auth).json()
    assert asset["os"] == "Linux 6.9.1"
    assert asset["ip_address"] == "10.0.0.99"
    assert (asset["asset_type"], asset["criticality"], asset["owner"]) == (
        "server",
        "critical",
        "Platform team",
    )


def test_scans_need_the_internal_token(client, auth, monkeypatch):
    body = scan(f"host-{uuid.uuid4().hex[:8]}")
    assert client.post("/api/v1/scans/", json=body).status_code == 401
    assert client.post("/api/v1/scans/", json=body, headers={"X-Internal-Token": "wrong"}).status_code == 401
    # A signed-in user is not one of UTDRS's services.
    assert client.post("/api/v1/scans/", json=body, headers=auth).status_code == 401

    monkeypatch.setattr(settings, "INTERNAL_API_TOKEN", None)
    assert client.post("/api/v1/scans/", json=body, headers=INTERNAL).status_code == 503


def test_a_malformed_scan_is_rejected(client):
    body = scan("")
    assert client.post("/api/v1/scans/", json=body, headers=INTERNAL).status_code == 422
