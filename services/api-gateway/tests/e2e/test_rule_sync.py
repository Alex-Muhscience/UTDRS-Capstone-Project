"""Rules edited through the gateway reach the core engine."""
import json
import os
import secrets
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from core.services import core_engine_client
from core.services.core_engine_client import CoreEngineClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)


class FakeEngine:
    """Keeps the managed rules the gateway sends, like the engine's PUT /rules/managed/gateway."""

    def __init__(self):
        self.rules = None
        self.calls = 0
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        assert request.url.path == "/rules/managed/gateway"
        assert request.headers["X-Internal-Token"] == "internal-token"
        self.calls += 1
        if self.fail:
            return httpx.Response(503, json={"detail": "engine unavailable"})
        self.rules = {r["source_id"]: r for r in json.loads(request.content)["rules"]}
        return httpx.Response(200, json={"stored": len(self.rules), "removed": 0})


@pytest.fixture
def engine(monkeypatch):
    fake = FakeEngine()
    monkeypatch.setattr(
        core_engine_client,
        "get_core_engine_client",
        lambda: CoreEngineClient("http://core-engine", token="internal-token", transport=httpx.MockTransport(fake.handler)),
    )
    return fake


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def admin(client):
    # The administrator created at start-up (see conftest).
    response = client.post(
        "/api/v1/auth/login",
        data={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]},
    )
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def rule(logic, **overrides):
    return {
        "name": f"rule-{uuid.uuid4().hex[:8]}",
        "description": "test rule",
        "rule_type": "signature",
        "detection_source": "endpoint",
        "severity": "high",
        "status": "enabled",
        "tags": ["T1059.001", "powershell"],
        "logic": logic,
        **overrides,
    }


RUNNABLE = "process_name == 'powershell.exe' and command_line matches '(?i)-enc'"


def test_a_new_rule_reaches_the_engine(client, admin, engine):
    response = client.post("/api/v1/detection/rules", json=rule(RUNNABLE), headers=admin)
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["engine"] == {"runs": True, "reason": None}

    sent = engine.rules[created["id"]]
    assert sent["name"] == created["name"]
    assert sent["enabled"] is True
    assert sent["detection"]["conditions"]["data.process_name"] == {"eq": "powershell.exe"}
    assert sent["mitre_techniques"] == ["T1059.001"]


def test_a_rule_the_engine_cannot_run_is_kept_but_not_sent(client, admin, engine):
    response = client.post("/api/v1/detection/rules", json=rule("event_type == 'dns' | count by source_ip > 10 in 5m"), headers=admin)
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["engine"]["runs"] is False
    assert "Aggregations" in created["engine"]["reason"]
    assert created["id"] not in engine.rules


def test_malformed_logic_is_refused(client, admin, engine):
    response = client.post("/api/v1/detection/rules", json=rule("process_name =="), headers=admin)
    assert response.status_code == 422
    assert "Rule logic" in response.json()["detail"]


def test_edits_and_disabling_reach_the_engine(client, admin, engine):
    created = client.post("/api/v1/detection/rules", json=rule(RUNNABLE), headers=admin).json()

    edited = client.put(
        f"/api/v1/detection/rules/{created['id']}",
        json={"logic": "process_name == 'pwsh.exe'", "severity": "critical"},
        headers=admin,
    )
    assert edited.status_code == 200, edited.text
    assert engine.rules[created["id"]]["severity"] == "critical"
    assert engine.rules[created["id"]]["detection"]["conditions"] == {"data.process_name": {"eq": "pwsh.exe"}}

    client.patch(f"/api/v1/detection/rules/{created['id']}/status", params={"status": "disabled"}, headers=admin)
    assert created["id"] not in engine.rules


def test_the_detection_status_reports_the_last_sync(client, admin, engine):
    client.post("/api/v1/detection/rules", json=rule(RUNNABLE), headers=admin)
    status = client.get("/api/v1/detection/", headers=admin).json()
    assert status["rule_sync"]["ok"] is True
    assert status["rule_sync"]["rules_sent"] == len(engine.rules)

    engine.fail = True
    client.post("/api/v1/detection/rules", json=rule(RUNNABLE), headers=admin)
    status = client.get("/api/v1/detection/", headers=admin).json()
    assert status["rule_sync"]["ok"] is False
    assert "503" in status["rule_sync"]["error"]
    assert status["rule_sync"]["succeeded_at"]  # the last success is still known
