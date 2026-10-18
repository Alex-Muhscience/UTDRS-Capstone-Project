"""Checking emails for phishing, from the recipient's mailbox."""
import base64
import json
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
MESSAGE_ID = "<phish-001@mail.evil.example>"


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
def engine(monkeypatch):
    """What reaches the engine: each event, with the data it was not stored with."""
    from core.services import detection_pipeline

    seen = []

    async def analyse_event(event_id, event, transient=None):
        seen.append({"event": event, "transient": transient})
        return None

    monkeypatch.setattr(detection_pipeline, "analyse_event", analyse_event)
    return seen


@pytest.fixture
def org(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"eml_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def connect(client, auth):
    from core.services import m365_ingest

    client.put(f"{API}/connectors/microsoft-365", json={"azure_tenant_id": AZURE_TENANT, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}, headers=auth)
    client.portal.call(m365_ingest.idle)


def email_events(client, auth):
    return [e for e in client.get(f"{API}/events/", params={"limit": 100}, headers=auth).json() if e["event_type"] == "email"]


def test_a_defender_alert_s_message_is_checked(client, org, microsoft, engine):
    connect(client, org)
    [event] = email_events(client, org)
    raw = event["raw_data"]
    assert (event["user_id"], raw["internet_message_id"], raw["sender"], raw["subject"]) == (
        "ana@contoso.example", MESSAGE_ID, "billing@evil.example", "Overdue invoice 4471: action required")
    assert (raw["spf"], raw["dkim"], raw["dmarc"]) == ("fail", "none", "fail")
    assert raw["external_sender"] is True and raw["reply_to"] == ["payments@collector.example"] and raw["reply_to_mismatch"] is True
    assert raw["links"] == ["https://login-micros0ft.evil.example/verify?u=ana&id=4471", "https://evil.example/invoice/4471"]
    assert raw["link_domains"] == ["evil.example", "login-micros0ft.evil.example"]
    [attachment] = raw["attachments"]
    assert attachment == {"name": "Invoice_4471.html", "type": "text/html", "size": 63, "risky": True,
                          "sha256": "f209933421d4ec34f0ebdf8139e8280285f1d4b7d8b5a5a7cad6de04cc7b42cf"}
    assert raw["risky_attachment"] is True and raw["sha256"] == attachment["sha256"]

    # The engine saw the body; UTDRS kept none of it.
    [email] = [e for e in engine if e["event"].event_type == "email"]
    assert "confirm your password" in email["transient"]["body"] and "<a " not in email["transient"]["body"]
    assert "confirm your password" not in json.dumps(event) and "body" not in raw

    # The Defender alert's event names the message, so they share a case.
    defender = next(e for e in client.get(f"{API}/events/", params={"limit": 100}, headers=org).json() if e["event_type"] == "security_alert")
    assert defender["raw_data"]["internet_message_id"] == MESSAGE_ID


def test_an_analyst_checks_a_message(client, org, microsoft, engine):
    connect(client, org)
    microsoft.messages_read.clear()
    again = client.post(f"{API}/email/check", json={"recipient": "ana@contoso.example", "internet_message_id": MESSAGE_ID}, headers=org).json()
    assert again["already_checked"] is True and microsoft.messages_read == ["ana@contoso.example"]
    assert len(email_events(client, org)) == 1  # once per mailbox and message

    response = client.post(f"{API}/email/check", json={"recipient": "bo@contoso.example", "internet_message_id": MESSAGE_ID}, headers=org)
    assert response.status_code == 404 and response.json()["detail"] == f"No message {MESSAGE_ID} in bo@contoso.example's mailbox"
    assert client.post(f"{API}/email/check", json={"recipient": "not-an-address", "internet_message_id": MESSAGE_ID}, headers=org).status_code == 422


def test_reported_messages_say_who_reported_them(client, org, microsoft, engine, monkeypatch):
    from core.services import m365_ingest

    monkeypatch.setattr(m365_ingest, "_check_messages", lambda record: _nothing())
    connect(client, org)
    result = client.post(f"{API}/email/check", json={"recipient": "ana@contoso.example", "internet_message_id": MESSAGE_ID}, headers=org).json()
    assert result["already_checked"] is False
    [event] = email_events(client, org)
    me = client.get(f"{API}/auth/me", headers=org).json()
    assert event["raw_data"]["reported_by"] == me["username"]


async def _nothing():
    return None


def test_checking_needs_microsoft_365(client, org):
    response = client.post(f"{API}/email/check", json={"recipient": "ana@contoso.example", "internet_message_id": MESSAGE_ID}, headers=org)
    assert response.status_code == 409 and response.json()["detail"] == "Microsoft 365 is not connected"


def test_the_email_rules_are_in_the_catalogue(client, org, microsoft, engine):
    connect(client, org)
    rules = {r["name"]: r for r in client.get(f"{API}/detection/rules", params={"limit": 500}, headers=org).json()}
    for name in ("Microsoft 365: email failed DMARC", "Microsoft 365: risky attachment from outside", "Microsoft 365: replies would go to someone else"):
        assert rules[name]["engine"]["runs"] and "phishing" in rules[name]["tags"], rules[name]
