"""Webhooks: signed, retried, logged, and never sent into a private network."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
URL = "https://1.1.1.1/hooks/utdrs"  # a public address, given as an IP so no DNS is needed


class Receiver:
    def __init__(self):
        self.received = []
        self.status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.received.append(request)
        return httpx.Response(self.status, text="ok" if self.status < 300 else "receiver is down")

    def events(self):
        return [json.loads(r.content)["type"] for r in self.received]


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def receiver(monkeypatch):
    from core.services import webhooks

    fake = Receiver()
    monkeypatch.setattr(webhooks, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    return fake


@pytest.fixture
def org(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"wh_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def deliver(client):
    from core.services import playbooks, webhooks

    client.portal.call(playbooks.idle)
    client.portal.call(webhooks.deliver_due)


def raise_alert(client, auth, **raw):
    event = client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr",
                                                 "description": "x", "raw_data": raw or {"user": f"u-{uuid.uuid4().hex[:4]}"}}, headers=auth).json()
    return client.post(f"{API}/alerts/", json={"title": "Odd process", "description": "x", "severity": "high", "source": "x", "type": "x",
                                                "event_ids": [event["id"]]}, headers=auth).json()


def test_events_arrive_signed(client, org, receiver):
    created = client.post(f"{API}/webhooks/", json={"name": "SOAR", "url": URL, "events": ["alert.created", "case.created", "case.updated"]}, headers=org)
    assert created.status_code == 201, created.text
    hook = created.json()
    secret = hook["signing_secret"]
    assert secret.startswith("whsec_") and "signing_secret" not in client.get(f"{API}/webhooks/", headers=org).json()[0]

    alert = raise_alert(client, org)
    deliver(client)
    assert sorted(receiver.events()) == ["alert.created", "case.created"]

    request = next(r for r in receiver.received if json.loads(r.content)["type"] == "alert.created")
    body = json.loads(request.content)
    assert body["data"]["id"] == alert["id"] and body["data"]["severity"] == "high" and body["data"]["url"].endswith(f"/alerts/{alert['id']}")
    assert request.headers["UTDRS-Event"] == "alert.created" and request.headers["UTDRS-Delivery"] == body["id"]
    # A receiver checks the signature over "<t>.<body>" with the secret, and that t is recent.
    parts = dict(p.split("=", 1) for p in request.headers["UTDRS-Signature"].split(","))
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + request.content, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(parts["v1"], expected) and abs(time.time() - int(parts["t"])) < 60

    client.patch(f"{API}/cases/{client.get(f'{API}/alerts/{alert['id']}', headers=org).json()['case_id']}", json={"status": "investigating"}, headers=org)
    deliver(client)
    update = json.loads(receiver.received[-1].content)
    assert update["type"] == "case.updated" and update["data"]["changes"] == {"status": {"before": "open", "after": "investigating"}}

    log = client.get(f"{API}/webhooks/{hook['id']}/deliveries", headers=org).json()
    assert {d["status"] for d in log} == {"delivered"} and all(d["response_status"] == 200 for d in log)
    assert client.get(f"{API}/webhooks/", headers=org).json()[0]["last_status"] == "ok"


def test_only_the_events_asked_for(client, org, receiver):
    client.post(f"{API}/webhooks/", json={"name": "Cases only", "url": URL, "events": ["case.created"]}, headers=org)
    raise_alert(client, org)
    deliver(client)
    assert receiver.events() == ["case.created"]


def test_failures_are_retried_then_given_up_and_can_be_sent_again(client, org, receiver):
    from core.services import webhooks

    hook = client.post(f"{API}/webhooks/", json={"name": "Flaky", "url": URL, "events": ["*"]}, headers=org).json()
    receiver.status = 503
    assert client.post(f"{API}/webhooks/{hook['id']}/test", headers=org).status_code == 202
    deliver(client)
    [first] = client.get(f"{API}/webhooks/{hook['id']}/deliveries", headers=org).json()
    assert first["event"] == "ping" and first["status"] == "queued" and first["attempts"] == 1
    assert first["response_status"] == 503 and "receiver is down" in first["error"]
    assert client.get(f"{API}/webhooks/", headers=org).json()[0]["last_status"] == "failing"

    async def due_now():
        from core.database.connection import get_database

        await get_database()["webhook_deliveries"].update_one({"_id": first["id"]}, {"$set": {"next_attempt_at": datetime.now(timezone.utc)}})

    for _ in range(webhooks.MAX_ATTEMPTS - 1):
        client.portal.call(due_now)
        deliver(client)
    [gave_up] = client.get(f"{API}/webhooks/{hook['id']}/deliveries", headers=org).json()
    assert gave_up["status"] == "failed" and gave_up["attempts"] == webhooks.MAX_ATTEMPTS

    receiver.status = 200
    assert client.post(f"{API}/webhooks/deliveries/{first['id']}/redeliver", headers=org).json()["status"] == "queued"
    deliver(client)
    [again] = client.get(f"{API}/webhooks/{hook['id']}/deliveries", headers=org).json()
    assert again["status"] == "delivered" and json.loads(receiver.received[-1].content)["id"] == first["id"]  # the same event id


@pytest.mark.parametrize("url", [
    "http://1.1.1.1/hook",  # not HTTPS
    "https://127.0.0.1/hook", "https://localhost/hook", "https://10.0.0.5/hook", "https://192.168.1.10/hook",
    "https://169.254.169.254/latest/meta-data", "https://[::1]/hook", "https://[::ffff:10.0.0.1]/hook",
    "https://user:pass@1.1.1.1/hook",
])
def test_private_and_unsafe_urls_are_refused(client, org, receiver, url):
    response = client.post(f"{API}/webhooks/", json={"name": "x", "url": url, "events": ["*"]}, headers=org)
    assert response.status_code == 422, (url, response.text)


def test_a_url_that_turns_private_is_not_sent_to(client, org, receiver, monkeypatch):
    from core.services import webhooks

    client.post(f"{API}/webhooks/", json={"name": "Rebinding", "url": URL, "events": ["*"]}, headers=org)

    async def now_private(url):
        raise webhooks.WebhookError("1.1.1.1 is a private or internal address; UTDRS only sends to public ones")

    monkeypatch.setattr(webhooks, "check_url", now_private)
    raise_alert(client, org)
    deliver(client)
    assert receiver.received == []


def test_private_receivers_when_the_deployment_allows(client, org, receiver, monkeypatch):
    monkeypatch.setattr(settings, "WEBHOOK_ALLOW_PRIVATE_ADDRESSES", True)
    assert client.post(f"{API}/webhooks/", json={"name": "Internal", "url": "http://10.0.0.5:8080/hook", "events": ["*"]}, headers=org).status_code == 201


def test_managing_webhooks(client, org, receiver):
    hook = client.post(f"{API}/webhooks/", json={"name": "A", "url": URL, "events": ["alert.created"]}, headers=org).json()
    assert client.post(f"{API}/webhooks/", json={"name": "B", "url": URL, "events": ["alert.nope"]}, headers=org).status_code == 422
    assert client.patch(f"{API}/webhooks/{hook['id']}", json={"enabled": False}, headers=org).json()["enabled"] is False
    raise_alert(client, org)
    deliver(client)
    assert receiver.received == []  # turned off

    rotated = client.post(f"{API}/webhooks/{hook['id']}/rotate-secret", headers=org).json()["signing_secret"]
    assert rotated != hook["signing_secret"]
    events = {e["name"] for e in client.get(f"{API}/webhooks/events", headers=org).json()}
    assert {"alert.created", "case.updated", "action.approval_requested", "connector.unhealthy", "report.ready"} <= events
    assert client.delete(f"{API}/webhooks/{hook['id']}", headers=org).status_code == 204
    assert client.get(f"{API}/webhooks/", headers=org).json() == []


def test_secrets_need_an_encryption_key(client, org, receiver, monkeypatch):
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
    response = client.post(f"{API}/webhooks/", json={"name": "x", "url": URL, "events": ["*"]}, headers=org)
    assert response.status_code == 422 and "ENCRYPTION_KEY" in response.json()["detail"]


def test_webhooks_are_kept_within_an_organisation_and_for_administrators(client, org, receiver, monkeypatch):
    hook = client.post(f"{API}/webhooks/", json={"name": "Mine", "url": URL, "events": ["*"]}, headers=org).json()
    username, password = f"wh_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}
    assert client.get(f"{API}/webhooks/", headers=other).json() == []
    assert client.delete(f"{API}/webhooks/{hook['id']}", headers=other).status_code == 404
    raise_alert(client, other)  # another organisation's events go to its own webhooks only
    deliver(client)
    assert receiver.received == []

    name = f"ana_{uuid.uuid4().hex[:6]}"
    temporary = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "analyst"}, headers=org).json()["temporary_password"]
    analyst = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': name, 'password': temporary}).json()['access_token']}"}
    assert client.get(f"{API}/webhooks/", headers=analyst).status_code == 403
