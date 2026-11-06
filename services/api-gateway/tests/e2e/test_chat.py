"""Slack and Microsoft Teams: messages where teams talk, and approving from Slack."""
import hashlib
import hmac
import json
import os
import time
import uuid
from urllib.parse import urlencode

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings
from tests.e2e.test_platform import key, sign_up  # noqa: F401  (fixture)
from tests.e2e.test_roles import person

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
TEAMS_URL = "https://prod-01.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=s3cret"
SLACK_HOOK = "https://hooks.slack.com/services/T000/B000/XXXX"
SIGNING = "slack-signing-secret"


class FakeChat:
    """Slack's and Teams' side: records what UTDRS sends, answers as they would."""

    def __init__(self):
        self.sent = []
        self.fail = False
        self.emails = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}") if request.method == "POST" else {}
        self.sent.append((str(request.url), body))
        if self.fail:
            return httpx.Response(500, text="down")
        path = request.url.path
        if path == "/api/auth.test":
            return httpx.Response(200, json={"ok": request.headers.get("authorization") == "Bearer xoxb-good"} | ({} if request.headers.get("authorization") == "Bearer xoxb-good" else {"error": "invalid_auth"}))
        if path == "/api/chat.postMessage":
            return httpx.Response(200, json={"ok": True, "ts": "1.2"})
        if path == "/api/users.info":
            user = request.url.params.get("user")
            return httpx.Response(200, json={"ok": True, "user": {"profile": {"email": self.emails.get(user, "")}}})
        return httpx.Response(202 if "logic.azure.com" in str(request.url) else 200, text="ok")


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def fake(monkeypatch):
    from core.services import chat

    fake = FakeChat()
    monkeypatch.setattr(chat, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "WEBHOOK_ALLOW_PRIVATE_ADDRESSES", True)  # no DNS in tests
    return fake


def deliver(client):
    from core.services import chat

    return client.portal.call(chat.deliver_due)


def alert(client, auth, severity):
    return client.post(f"{API}/alerts/", json={"title": f"{severity} {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity,
                                               "source": "x", "type": "x"}, headers=auth).json()


def test_administrators_add_teams_and_slack_channels(client, monkeypatch, fake):
    _, admin = sign_up(client, monkeypatch, "ca")
    analyst, _ = person(client, admin, "analyst")
    teams = {"name": "SOC", "kind": "teams", "events": ["alert.created"], "webhook_url": TEAMS_URL}
    assert client.post(f"{API}/chat/channels", json=teams, headers=analyst).status_code == 403
    wrong = client.post(f"{API}/chat/channels", json={**teams, "webhook_url": "https://example.com/hook"}, headers=admin)
    assert wrong.status_code == 422 and "Workflows" in wrong.json()["detail"]
    created = client.post(f"{API}/chat/channels", json=teams, headers=admin)
    assert created.status_code == 201 and "webhook_url" not in created.json() and "sig=" not in created.text
    bad_app = client.post(f"{API}/chat/channels", json={"name": "S", "kind": "slack_app", "events": ["alert.created"], "bot_token": "xoxb-bad",
                                                        "signing_secret": SIGNING, "slack_channel": "C1"}, headers=admin)
    assert bad_app.status_code == 422 and "invalid_auth" in bad_app.json()["detail"]
    # The URL is a credential: the audit log does not keep it.
    log = client.get(f"{API}/audit-log/", params={"action": "chat"}, headers=admin).json()
    assert log and "s3cret" not in json.dumps(log)


def test_serious_alerts_reach_teams_as_cards_and_failures_are_retried(client, monkeypatch, fake):
    _, admin = sign_up(client, monkeypatch, "cb")
    channel = client.post(f"{API}/chat/channels", json={"name": "SOC", "kind": "teams", "events": ["alert.created"], "min_alert_severity": "high",
                                                        "webhook_url": TEAMS_URL}, headers=admin).json()
    alert(client, admin, "medium")
    serious = alert(client, admin, "critical")
    deliver(client)
    cards = [body for url, body in fake.sent if "logic.azure.com" in url]
    assert len(cards) == 1
    card = cards[0]["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and serious["title"] in card["body"][0]["text"]
    assert card["actions"][0]["url"].endswith(f"/alerts/{serious['id']}")
    assert client.get(f"{API}/chat/channels", headers=admin).json()[0]["last_status"] == "ok"

    fake.fail = True
    alert(client, admin, "high")
    deliver(client)
    messages = client.get(f"{API}/chat/channels/{channel['id']}/messages", headers=admin).json()
    assert messages[0]["status"] == "queued" and messages[0]["attempts"] == 1 and "500" in messages[0]["error"]
    assert client.get(f"{API}/chat/channels", headers=admin).json()[0]["last_status"] == "failing"
    test = client.post(f"{API}/chat/channels/{channel['id']}/test", headers=admin)
    assert test.status_code == 422 and "Teams answered 500" in test.json()["detail"]


def test_slack_webhooks_get_blocks_with_a_link(client, monkeypatch, fake):
    _, admin = sign_up(client, monkeypatch, "cc")
    client.post(f"{API}/chat/channels", json={"name": "Alerts", "kind": "slack_webhook", "events": ["alert.created"], "min_alert_severity": "low",
                                              "webhook_url": SLACK_HOOK}, headers=admin)
    raised = alert(client, admin, "low")
    deliver(client)
    body = next(body for url, body in fake.sent if url == SLACK_HOOK)
    assert raised["title"] in body["text"]
    buttons = body["blocks"][-1]["elements"]
    assert [b.get("action_id") for b in buttons] == ["utdrs_open"]  # a webhook cannot take decisions


def slack_click(client, channel_id, action_id, value, slack_user, secret=SIGNING, when=None):
    payload = {"type": "block_actions", "user": {"id": slack_user}, "response_url": "https://hooks.slack.com/actions/T/1/abc",
               "actions": [{"action_id": action_id, "value": value}]}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    timestamp = str(int(when or time.time()))
    signature = "v0=" + hmac.new(secret.encode(), f"v0:{timestamp}:".encode() + body, hashlib.sha256).hexdigest()
    return client.post(f"{API}/chat/slack/{channel_id}/interactions", content=body,
                       headers={"X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": signature, "Content-Type": "application/x-www-form-urlencoded"})


def pending_action(client, tenant_id, case_id):
    from core.services import response_actions
    from core.tenancy import tenant_context

    async def propose():
        with tenant_context(tenant_id):
            return await response_actions.request("utdrs.escalate_case", {"type": "case", "value": case_id}, {"priority": "critical"},
                                                  actor={"type": "user", "id": "x", "name": "tester"}, case_id=case_id, mode="approval")

    return client.portal.call(propose)


def test_actions_are_approved_from_slack_by_people_allowed_to(client, monkeypatch, fake):
    from core.services import chat

    _, admin = sign_up(client, monkeypatch, "cd")
    tenant_id = client.get(f"{API}/tenants/current", headers=admin).json()["id"]
    _, analyst_account = person(client, admin, "analyst")
    _, viewer_account = person(client, admin, "viewer")
    fake.emails = {"U_ANALYST": analyst_account["email"], "U_VIEWER": viewer_account["email"], "U_STRANGER": "nobody@elsewhere.example"}
    channel = client.post(f"{API}/chat/channels", json={"name": "SOC", "kind": "slack_app", "events": ["action.approval_requested"],
                                                        "bot_token": "xoxb-good", "signing_secret": SIGNING, "slack_channel": "C123"}, headers=admin).json()
    assert channel["interactions_url"].endswith(f"/chat/slack/{channel['id']}/interactions")

    case_id = client.get(f"{API}/alerts/{alert(client, admin, 'low')['id']}", headers=admin).json()["case_id"]
    action = pending_action(client, tenant_id, case_id)
    assert action["status"] == "pending"
    deliver(client)
    posted = next(body for url, body in fake.sent if url.endswith("/chat.postMessage"))
    assert posted["channel"] == "C123"
    assert [b.get("action_id") for b in posted["blocks"][-1]["elements"]] == ["utdrs_approve", "utdrs_reject", "utdrs_open"]

    # Not Slack: a wrong signature, or an old request, is refused.
    assert slack_click(client, channel["id"], "utdrs_approve", action["id"], "U_ANALYST", secret="wrong").status_code == 401
    assert slack_click(client, channel["id"], "utdrs_approve", action["id"], "U_ANALYST", when=time.time() - 3600).status_code == 401

    # Genuine, but not someone who may decide: nothing happens, and they are told why.
    for who in ("U_STRANGER", "U_VIEWER"):
        assert slack_click(client, channel["id"], "utdrs_approve", action["id"], who).status_code == 200
        client.portal.call(chat.idle)
    replies = [body["text"] for url, body in fake.sent if url == "https://hooks.slack.com/actions/T/1/abc"]
    assert "not a UTDRS account" in replies[0] and "role does not let you" in replies[1]
    assert client.get(f"{API}/response/actions/{action['id']}", headers=admin).json()["status"] == "pending"

    assert slack_click(client, channel["id"], "utdrs_approve", action["id"], "U_ANALYST").status_code == 200
    client.portal.call(chat.idle)
    decided = client.get(f"{API}/response/actions/{action['id']}", headers=admin).json()
    assert decided["status"] == "succeeded" and decided["decided_by"]["name"] == analyst_account["username"]
    replies = [body for url, body in fake.sent if url == "https://hooks.slack.com/actions/T/1/abc"]
    assert replies[-1]["replace_original"] is True and "Approved by" in replies[-1]["text"]
    log = client.get(f"{API}/audit-log/", params={"action": "response"}, headers=admin).json()
    assert any(e["details"] and e["details"].get("via") == "slack" for e in log)
