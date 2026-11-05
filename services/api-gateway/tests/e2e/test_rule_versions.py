"""Detection rules: test cases that must pass, and versions that can be restored."""
import os
import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1/detection"
LOGIC = "process_name == 'powershell.exe' and command_line matches '(?i)-enc'"
CASES = [
    {"name": "Encoded PowerShell", "event": {"event_type": "process", "source": "edr", "raw_data": {"process_name": "powershell.exe", "command_line": "powershell -Enc SQBFAFgA"}}},
    {"name": "Plain PowerShell", "event": {"event_type": "process", "process_name": "powershell.exe", "command_line": "Get-Date"}, "expect": "no_match"},
    {"name": "No process", "event": {"event_type": "authentication"}, "expect": "no_match"},
]


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"rv_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post("/api/v1/auth/register", json={**credentials, "email": f"rv_{suffix}@example.com", "organisation": f"Org {suffix}"})
    return {"Authorization": f"Bearer {client.post('/api/v1/auth/login', data=credentials).json()['access_token']}"}


def new_rule(client, admin, **fields):
    body = {"name": f"Encoded PowerShell {uuid.uuid4().hex[:6]}", "description": "x", "rule_type": "signature", "detection_source": "endpoint",
            "severity": "high", "logic": LOGIC, "test_cases": CASES, **fields}
    return client.post(f"{API}/rules", json=body, headers=admin)


def test_test_cases_say_what_the_engine_would_match(client, admin):
    run = client.post(f"{API}/rules/test", json={"logic": LOGIC, "test_cases": CASES}, headers=admin).json()
    assert run["ran"] and run["passed"]
    assert [r["matched"] for r in run["results"]] == [True, False, False]

    wrong = client.post(f"{API}/rules/test", json={"logic": "process_name == 'cmd.exe'", "test_cases": CASES}, headers=admin).json()
    assert wrong["passed"] is False and wrong["results"][0]["passed"] is False

    unsupported = client.post(f"{API}/rules/test", json={"logic": "event_type == 'x' | distinct source_ip", "test_cases": CASES}, headers=admin).json()
    assert unsupported["ran"] is False and "not run by the engine" in unsupported["reason"]


def test_a_rule_whose_tests_fail_is_not_saved(client, admin):
    refused = new_rule(client, admin, logic="process_name == 'cmd.exe'")
    assert refused.status_code == 422 and "test cases fail" in refused.json()["detail"]

    rule = new_rule(client, admin).json()
    broken = client.put(f"{API}/rules/{rule['id']}", json={"logic": "process_name == 'cmd.exe'"}, headers=admin)
    assert broken.status_code == 422
    assert client.post(f"{API}/rules/{rule['id']}/test", headers=admin).json()["passed"] is True


def test_every_change_is_a_version_and_an_old_one_can_be_restored(client, admin):
    rule = new_rule(client, admin).json()
    assert rule["version"] == 1
    client.put(f"{API}/rules/{rule['id']}", json={"severity": "critical"}, headers=admin)
    client.patch(f"{API}/rules/{rule['id']}/status", params={"status": "disabled"}, headers=admin)
    client.post(f"{API}/rules/{rule['id']}/tags/T1059.001", headers=admin)

    history = client.get(f"{API}/rules/{rule['id']}/versions", headers=admin).json()
    assert [v["version"] for v in history] == [4, 3, 2, 1]
    assert [v["change"] for v in history] == ["tag added: T1059.001", "status: disabled", "updated", "created"]
    assert history[-1]["rule"]["severity"] == "high" and history[0]["rule"]["severity"] == "critical"

    restored = client.post(f"{API}/rules/{rule['id']}/versions/1/restore", headers=admin)
    assert restored.status_code == 200, restored.text
    assert (restored.json()["severity"], restored.json()["status"], restored.json()["version"]) == ("high", "enabled", 5)
    latest = client.get(f"{API}/rules/{rule['id']}/versions", headers=admin).json()[0]
    assert latest["change"] == "restored from version 1"


def test_versions_stay_in_their_organisation(client, admin, monkeypatch):
    rule = new_rule(client, admin).json()
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"rv_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post("/api/v1/auth/register", json={**credentials, "email": f"rv_{suffix}@example.com", "organisation": f"Other {suffix}"})
    other = {"Authorization": f"Bearer {client.post('/api/v1/auth/login', data=credentials).json()['access_token']}"}
    assert client.get(f"{API}/rules/{rule['id']}/versions", headers=other).status_code == 404
    assert client.post(f"{API}/rules/{rule['id']}/versions/1/restore", headers=other).status_code == 404
