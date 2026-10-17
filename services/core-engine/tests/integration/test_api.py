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


def test_predefined_rules_are_loaded_once_at_startup(client):
    from core.rules.predefined.rules import get_predefined_rules
    from core.rules.rule_loader import RuleManager

    names = {rule["name"] for rule in get_predefined_rules()}
    stored = {rule["name"] for rule in client.get("/rules/", params={"limit": 500}).json()}
    assert names <= stored
    # Loading again adds nothing: rules are matched by name.
    assert client.portal.call(RuleManager().load_predefined_rules) == 0


def test_a_signature_rule_produces_an_alert(client):
    failed_login = {
        "source": "vpn-gw",
        "event_type": "authentication",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"status": "failed", "user_id": "admin", "source_ip": "185.220.101.4"},
    }
    response = client.post("/detections/process", json=failed_login)
    assert response.status_code == 200, response.text
    alert = response.json()
    assert alert["detection_type"] == "signature"
    assert alert["title"] == "Multiple Failed Login Attempts"
    assert "T1110" in alert["details"]["mitre_techniques"]


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


def test_without_a_token_the_engine_refuses_requests(client, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "INTERNAL_API_TOKEN", None)
    monkeypatch.setattr(settings, "ALLOW_UNAUTHENTICATED", False)
    assert client.get("/detections/alerts").status_code == 503
    assert client.post("/detections/process", json=RANSOMWARE_PRECURSOR).status_code == 503
    assert client.get("/health").status_code == 200


def managed_rule(source_id, **overrides):
    return {
        "source_id": source_id,
        "name": f"Sync test ({source_id})",
        "description": "A test process with a marker argument",
        "detection": {
            "condition_type": "AND",
            "conditions": {
                # A process no built-in rule knows, so only this rule can match.
                "data.process_name": {"eq": "utdrs-sync-test.exe"},
                "data.command_line": {"search": "(?i)--sync-marker"},
            },
        },
        "severity": "high",
        "tags": ["T1059.001"],
        **overrides,
    }


MARKED_PROCESS = {
    "source": "endpoint_agent",
    "event_type": "process",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "data": {"process_name": "utdrs-sync-test.exe", "command_line": "utdrs-sync-test --SYNC-MARKER"},
}


def test_managed_rules_are_replaced_as_a_set_and_detect(client):
    response = client.put("/rules/managed/gateway", json={"rules": [managed_rule("r1"), managed_rule("r2")]})
    assert response.json() == {"stored": 2, "removed": 0}

    alert = client.post("/detections/process", json=MARKED_PROCESS).json()
    assert alert is not None
    assert alert["details"]["detection"]["rule_source"] == "gateway"
    assert alert["details"]["detection"]["rule_source_id"] in {"r1", "r2"}

    # r1 is edited, r2 is gone.
    response = client.put("/rules/managed/gateway", json={"rules": [managed_rule("r1", severity="critical")]})
    assert response.json() == {"stored": 1, "removed": 1}
    managed = client.get("/rules/", params={"source": "gateway"}).json()
    assert [(r["source_id"], r["severity"]) for r in managed] == [("r1", "critical")]

    # Built-in rules are not touched, and a disabled managed rule stops detecting.
    assert len(client.get("/rules/", params={"source": "builtin"}).json()) > 0
    client.put("/rules/managed/gateway", json={"rules": [managed_rule("r1", enabled=False)]})
    assert client.post("/detections/process", json=MARKED_PROCESS).json() is None

    client.put("/rules/managed/gateway", json={"rules": []})
    assert client.get("/rules/", params={"source": "gateway"}).json() == []


def test_an_invalid_managed_rule_changes_nothing(client):
    client.put("/rules/managed/gateway", json={"rules": [managed_rule("keep")]})
    bad = managed_rule("bad", detection={"condition_type": "AND"})  # no conditions
    response = client.put("/rules/managed/gateway", json={"rules": [managed_rule("new"), bad]})
    assert response.status_code == 422
    assert [r["source_id"] for r in client.get("/rules/", params={"source": "gateway"}).json()] == ["keep"]
    client.put("/rules/managed/gateway", json={"rules": []})
