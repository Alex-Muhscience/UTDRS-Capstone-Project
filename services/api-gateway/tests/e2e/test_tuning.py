"""Detection tuning: verdicts, suppressions, detector quality and labels."""
import json
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


@pytest.fixture
def org(client, monkeypatch):
    """A new organisation's administrator, so suppressions from other tests do not apply."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"tun_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


@pytest.fixture
def analyst(client, org):
    """An analyst in the same organisation as `org`."""
    username = f"ana_{uuid.uuid4().hex[:6]}"
    response = client.post(f"{API}/users/", json={"username": username, "email": f"{username}@example.com", "role": "analyst"}, headers=org)
    token = client.post(f"{API}/auth/login", data={"username": username, "password": response.json()["temporary_password"]}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def raise_alert(client, auth, severity="medium", tags=(), title="Port scan", **raw):
    event = client.post(
        f"{API}/events/",
        json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "network", "source": "ids", "description": "x", "raw_data": raw},
        headers=auth,
    ).json()
    alert = client.post(
        f"{API}/alerts/",
        json={"title": title, "description": "x", "severity": severity, "source": "core-engine", "type": "signature", "tags": list(tags), "event_ids": [event["id"]]},
        headers=auth,
    ).json()
    from core.services import playbooks

    client.portal.call(playbooks.idle)
    return client.get(f"{API}/alerts/{alert['id']}", headers=auth).json()


def suppress(client, auth, **body):
    return client.post(f"{API}/tuning/suppressions", json={"name": "Test", "reason": "Our scanner", **body}, headers=auth)


def test_a_false_positive_is_marked_kept_as_a_label_and_suggests_a_suppression(client, org):
    alert = raise_alert(client, org, "medium", title="Port scan", source_ip="10.0.0.9")
    result = client.post(f"{API}/alerts/{alert['id']}/feedback", json={"verdict": "false_positive", "note": "Our vulnerability scanner"}, headers=org)
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["alert"]["status"] == "false_positive" and body["alert"]["feedback"]["verdict"] == "false_positive"
    assert body["alert"]["feedback"]["note"] == "Our vulnerability scanner" and body["alert"]["feedback"]["by"]["type"] == "user"
    assert body["suggestion"] == {"name": "Port scan — 10.0.0.9", "detector": "signature:Port scan", "entity": {"type": "ip", "value": "10.0.0.9"}, "max_severity": "medium"}

    timeline = client.get(f"{API}/cases/{alert['case_id']}", headers=org).json()["timeline"]
    assert timeline[-1]["kind"] == "feedback" and timeline[-1]["text"] == "\"Port scan\" marked a false positive: Our vulnerability scanner"

    # Changing one's mind replaces the label.
    client.post(f"{API}/alerts/{alert['id']}/feedback", json={"verdict": "true_positive"}, headers=org)
    labels = [json.loads(line) for line in client.get(f"{API}/tuning/labels", headers=org).text.splitlines()]
    [label] = [l for l in labels if l["alert_id"] == alert["id"]]
    assert label["verdict"] == "true_positive" and label["detector"] == "signature:Port scan"
    assert label["events"][0]["raw_data"] == {"source_ip": "10.0.0.9"} and "tenant_id" not in label["events"][0]


def test_benign_closes_and_true_positive_leaves_it_open(client, org):
    benign = raise_alert(client, org, title="Admin tool run", user="it")
    real = raise_alert(client, org, title="Mimikatz", user="bob")
    assert client.post(f"{API}/alerts/{benign['id']}/feedback", json={"verdict": "benign"}, headers=org).json()["alert"]["status"] == "closed"
    result = client.post(f"{API}/alerts/{real['id']}/feedback", json={"verdict": "true_positive"}, headers=org).json()
    assert result["alert"]["status"] == "open" and result["suggestion"] is None
    assert client.post(f"{API}/alerts/{real['id']}/feedback", json={"verdict": "maybe"}, headers=org).status_code == 422
    assert client.post(f"{API}/alerts/665f1c2ab1e2c3d4e5f6ffff/feedback", json={"verdict": "benign"}, headers=org).status_code == 404


def test_an_allow_listed_address_is_suppressed_and_reaches_nobody(client, org):
    response = suppress(client, org, entity={"type": "ip", "value": "10.0.0.9"})
    assert response.status_code == 201, response.text
    suppression = response.json()
    assert suppression["max_severity"] == "high" and suppression["enabled"] is True
    assert datetime.fromisoformat(suppression["expires_at"]) > datetime.now(timezone.utc) + timedelta(days=89)

    hidden = raise_alert(client, org, "high", ["ransomware"], title="Port scan", source_ip="10.0.0.9")
    assert hidden["status"] == "suppressed" and hidden["suppressed_by"] == suppression["id"] and hidden["case_id"] is None
    assert client.get(f"{API}/response/actions", headers=org).json() == []  # no playbook ran
    seen = raise_alert(client, org, "high", title="Port scan", source_ip="10.0.0.10")
    assert seen["status"] == "open" and seen["case_id"]

    [listed] = client.get(f"{API}/tuning/suppressions", headers=org).json()
    assert listed["hits"] == 1 and listed["last_hit_at"]


def test_critical_alerts_get_through_unless_an_administrator_says(client, org):
    suppress(client, org, title_contains="port SCAN")
    assert raise_alert(client, org, "critical", title="Port scan from outside")["status"] == "open"
    assert raise_alert(client, org, "high", title="Port scan from outside")["status"] == "suppressed"
    suppress(client, org, title_contains="Beacon", max_severity="critical", expires_in_days=None)
    assert raise_alert(client, org, "critical", title="Beacon to known C2")["status"] == "suppressed"


def test_detector_and_entity_must_both_match(client, org):
    suppress(client, org, detector="signature:Failed sign-ins", entity={"type": "user", "value": "SVC-Backup"})
    assert raise_alert(client, org, title="Failed sign-ins", user="svc-backup")["status"] == "suppressed"  # names compared without case
    assert raise_alert(client, org, title="Failed sign-ins", user="ana")["status"] == "open"
    assert raise_alert(client, org, title="Odd process", user="svc-backup")["status"] == "open"


def test_expired_and_disabled_suppressions_do_not_apply(client, org):
    off = suppress(client, org, title_contains="Noisy").json()
    client.patch(f"{API}/tuning/suppressions/{off['id']}", json={"enabled": False}, headers=org)
    assert raise_alert(client, org, title="Noisy thing")["status"] == "open"

    old = suppress(client, org, title_contains="Stale").json()

    async def expire():
        from bson import ObjectId
        from core.database.connection import get_database

        await get_database()["suppressions"].update_one({"_id": ObjectId(old["id"])}, {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}})

    client.portal.call(expire)
    assert raise_alert(client, org, title="Stale thing")["status"] == "open"
    assert client.delete(f"{API}/tuning/suppressions/{old['id']}", headers=org).status_code == 204
    assert client.delete(f"{API}/tuning/suppressions/{old['id']}", headers=org).status_code == 404


def test_what_analysts_may_suppress(client, org, analyst):
    assert suppress(client, analyst, title_contains="x").status_code == 201
    assert suppress(client, analyst, title_contains="x", expires_in_days=None).status_code == 403
    response = suppress(client, analyst, title_contains="x", max_severity="critical")
    assert response.status_code == 403 and response.json()["detail"] == "Only an administrator can suppress critical alerts"
    mine = suppress(client, analyst, title_contains="y").json()
    assert client.patch(f"{API}/tuning/suppressions/{mine['id']}", json={"expires_in_days": 0}, headers=analyst).status_code == 403
    assert client.patch(f"{API}/tuning/suppressions/{mine['id']}", json={"expires_in_days": 0}, headers=org).json()["expires_at"] is None
    assert client.post(f"{API}/tuning/suppressions", json={"name": "Nothing", "reason": "x"}, headers=analyst).status_code == 422
    assert client.get(f"{API}/tuning/labels", headers=analyst).status_code == 403


def test_noisy_detectors_are_found(client, org):
    for _ in range(5):
        alert = raise_alert(client, org, title="DNS tunnelling", user=f"u{uuid.uuid4().hex[:4]}")
        client.post(f"{API}/alerts/{alert['id']}/feedback", json={"verdict": "false_positive"}, headers=org)
    good = raise_alert(client, org, title="Ransom note written", host="ws-9")
    client.post(f"{API}/alerts/{good['id']}/feedback", json={"verdict": "true_positive"}, headers=org)
    raise_alert(client, org, title="Unjudged")

    rows = client.get(f"{API}/tuning/quality", headers=org).json()
    assert rows[0] == {"detector": "signature:DNS tunnelling", "name": "DNS tunnelling", "alerts": 5, "suppressed": 0, "true_positive": 0,
                       "false_positive": 5, "benign": 0, "precision": 0.0, "noisy": True}
    by = {r["detector"]: r for r in rows}
    assert by["signature:Ransom note written"]["precision"] == 1.0 and not by["signature:Ransom note written"]["noisy"]
    assert by["signature:Unjudged"]["precision"] is None


def test_tuning_is_kept_within_an_organisation(client, org, monkeypatch):
    suppression = suppress(client, org, title_contains="Mine").json()
    alert = raise_alert(client, org, title="Theirs")
    username, password = f"tun_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}

    assert client.get(f"{API}/tuning/suppressions", headers=other).json() == []
    assert client.patch(f"{API}/tuning/suppressions/{suppression['id']}", json={"enabled": False}, headers=other).status_code == 404
    assert client.post(f"{API}/alerts/{alert['id']}/feedback", json={"verdict": "benign"}, headers=other).status_code == 404
    assert raise_alert(client, other, title="Mine too")["status"] == "open"  # another organisation's suppression does not apply
    assert client.get(f"{API}/tuning/labels", headers=other).text == ""

    key = client.post(f"{API}/api-keys/", json={"name": "k", "scopes": ["alerts:read"]}, headers=org).json()["key"]
    assert client.get(f"{API}/tuning/quality", headers={"Authorization": f"Bearer {key}"}).status_code == 403


def test_marking_a_false_positive_by_status_is_a_verdict_too(client, org):
    alert = raise_alert(client, org, title="Odd login", user="kim")
    assert client.patch(f"{API}/alerts/{alert['id']}/status", params={"status": "false_positive", "notes": "VPN"}, headers=org).status_code == 200
    feedback = client.get(f"{API}/alerts/{alert['id']}", headers=org).json()["feedback"]
    assert feedback["verdict"] == "false_positive" and feedback["note"] == "VPN"
    assert any(json.loads(line)["alert_id"] == alert["id"] for line in client.get(f"{API}/tuning/labels", headers=org).text.splitlines())
