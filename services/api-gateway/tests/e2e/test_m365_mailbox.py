"""Exchange's mailbox audit: inbox rules and forwarding, from the Office 365 Management Activity API."""
import base64
import os
import secrets
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings
from tests.e2e.test_m365 import AZURE_TENANT, CLIENT_ID, CLIENT_SECRET, FakeMicrosoft

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
def microsoft(monkeypatch):
    from core.services import m365

    fake = FakeMicrosoft()
    monkeypatch.setattr(m365, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    m365._tokens.clear()
    return fake


@pytest.fixture
def org(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"mbx_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def connect(client, auth):
    from core.services import m365_ingest

    response = client.put(f"{API}/connectors/microsoft-365", json={"azure_tenant_id": AZURE_TENANT, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}, headers=auth)
    client.portal.call(m365_ingest.idle)
    return response


def mailbox_events(client, auth):
    return {e["raw_data"]["external_id"]: e for e in client.get(f"{API}/events/", params={"limit": 100}, headers=auth).json() if e["event_type"] == "mailbox"}


def test_inbox_rules_and_forwarding_become_events(client, org, microsoft):
    connect(client, org)
    assert "https://manage.office.com/.default" in microsoft.scopes and microsoft.subscribed == 1
    events = mailbox_events(client, org)
    assert len(events) == 3  # mail access and other mailbox settings are not kept

    rule = events["exchange:8b1e2f3a-0001-4c5d-9e8f-0a1b2c3d4e5f"]
    assert (rule["user_id"], rule["source_ip"], rule["action"]) == ("jsmith@contoso.example", "203.0.113.45", "New-InboxRule")
    raw = rule["raw_data"]
    assert raw["rule_name"] == "invoices" and raw["forward_to"] == ["acct-payables@evil.example"]
    assert raw["external_forward"] is True and raw["hides_mail"] is True and raw["move_to_folder"] == "RSS Subscriptions"
    assert raw["keywords"] == ["invoice", "payment", "wire"]
    assert rule["description"] == 'jsmith@contoso.example created the inbox rule "invoices": forwards to acct-payables@evil.example; hides mail in RSS Subscriptions'

    inside = events["exchange:8b1e2f3a-0002-4c5d-9e8f-0a1b2c3d4e5f"]["raw_data"]
    assert inside["forward_to"] == ["deputy@contoso.example"] and inside["external_forward"] is False and inside["hides_mail"] is False

    forwarding = events["exchange:8b1e2f3a-0003-4c5d-9e8f-0a1b2c3d4e5f"]
    assert forwarding["source_ip"] == "2001:db8::7" and forwarding["raw_data"]["external_addresses"] == ["bo.private@gmail.example"]
    assert forwarding["raw_data"]["rule_name"] is None

    # Polling again neither subscribes again nor stores anything twice.
    assert client.post(f"{API}/connectors/microsoft-365/poll", headers=org).json()["counts"]["mailbox"] == 0
    assert microsoft.subscribed == 1


def test_the_mailbox_rules_are_in_the_catalogue(client, org, microsoft):
    connect(client, org)
    rules = {r["name"]: r for r in client.get(f"{API}/detection/rules", params={"limit": 500}, headers=org).json()}
    for name in ("Microsoft 365: inbox rule forwards mail outside", "Microsoft 365: mailbox forwards mail outside", "Microsoft 365: inbox rule hides mail"):
        assert rules[name]["engine"]["runs"], rules[name]["engine"]
    assert "T1114.003" in rules["Microsoft 365: inbox rule forwards mail outside"]["tags"]


def test_without_permission_only_the_mailbox_stops(client, org, microsoft):
    microsoft.management_forbidden = True
    connect(client, org)
    status = client.get(f"{API}/connectors/microsoft-365", headers=org).json()
    assert status["errors"] == {"mailbox": "Not allowed: needs ActivityFeed.Read (Office 365 Management APIs)"}
    assert status["last_poll"]["signins"] == 3
    check = next(c for c in status["checks"] if c["name"] == "Exchange mailbox audit")
    assert check["ok"] is False and "ActivityFeed.Read" in check["detail"]


def test_the_playbook_removes_the_rule_by_its_name(client, org, microsoft):
    connect(client, org)
    microsoft.rules[("jsmith@contoso.example", "AQAAAJ5dZp8=")] = {"id": "AQAAAJ5dZp8=", "displayName": "invoices", "actions": {"forwardTo": []}}
    event = mailbox_events(client, org)["exchange:8b1e2f3a-0001-4c5d-9e8f-0a1b2c3d4e5f"]
    # As the engine would raise it from the "forwards mail outside" rule.
    alert = client.post(f"{API}/alerts/", json={"title": "Microsoft 365: inbox rule forwards mail outside", "description": "x", "severity": "high",
                                                 "source": "core-engine", "type": "signature", "tags": ["email", "inbox-rule", "T1114.003"],
                                                 "event_ids": [event["id"]]}, headers=org).json()
    from core.services import playbooks

    client.portal.call(playbooks.idle)
    case_id = client.get(f"{API}/alerts/{alert['id']}", headers=org).json()["case_id"]
    actions = {a["action"]: a for a in client.get(f"{API}/response/actions", params={"case_id": case_id}, headers=org).json()}
    remove = actions["m365.remove_inbox_rule"]
    assert remove["params"] == {"rule_name": "invoices"} and remove["playbook"]["name"] == "Malicious inbox rule"
    assert "m365.revoke_sessions" in actions

    done = client.post(f"{API}/response/actions/{remove['id']}/approve", headers=org).json()
    assert done["status"] == "succeeded" and done["result"]["summary"] == 'Removed the inbox rule "invoices"'
    assert not microsoft.rules and done["can_undo"]


def test_removing_a_rule_that_is_gone_says_so(client, org, microsoft):
    connect(client, org)
    action = client.post(f"{API}/response/actions", json={"action": "m365.remove_inbox_rule", "target": {"type": "user", "value": "kim@contoso.example"},
                                                           "params": {"rule_name": "nothing"}}, headers=org).json()
    assert action["status"] == "failed" and action["error"] == 'kim@contoso.example has no inbox rule called "nothing" (it may already be gone)'
    response = client.post(f"{API}/response/actions", json={"action": "m365.remove_inbox_rule", "target": {"type": "user", "value": "kim@contoso.example"}}, headers=org)
    assert response.status_code == 422 and response.json()["detail"] == "Remove an inbox rule needs rule_id or rule_name"
