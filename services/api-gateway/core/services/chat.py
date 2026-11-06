"""
Slack and Microsoft Teams: what needs attention, where an organisation's team already talks.

An organisation's administrators add channels of three kinds:

- **Slack, incoming webhook**: messages only, each with a button that opens UTDRS.
- **Slack app** (the organisation's own app, with its bot token and signing secret): messages,
  and response actions approved or rejected from Slack itself. Each click is checked with
  Slack's signature, made by the Slack user whose email is a UTDRS account in the organisation,
  and only if their role lets them decide (administrators, for a protected account).
- **Microsoft Teams** (a Workflows "post to a channel when a webhook request is received"
  URL): Adaptive Cards, with a button that opens UTDRS. Deciding stays in UTDRS: in-Teams
  buttons would need an Azure bot registration.

Each channel chooses its events: new alerts (from a minimum severity), new cases, actions
waiting for a decision, failed actions, monthly reports, failing connectors. Messages are queued
and sent by a background loop, retried for about an hour, and the channel shows how sending went.
Secrets (webhook URLs, which are credentials, and bot tokens) are stored encrypted.
"""
import asyncio
import hashlib
import hmac
import json
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import httpx
from bson import ObjectId
from pymongo import ReturnDocument

from config import settings
from core.database.connection import get_database
from core.tenancy import current_tenant_or_none, scoped, tenant_context
from utils import crypto
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

KINDS = ("slack_webhook", "slack_app", "teams")
EVENTS: Dict[str, str] = {
    "alert.created": "A new alert, from the channel's minimum severity",
    "case.created": "A new case",
    "action.approval_requested": "A response action waiting for a decision",
    "action.failed": "A response action that failed",
    "report.ready": "A monthly report was made",
    "connector.unhealthy": "A connector stopped bringing data in",
}
SEVERITIES = ["info", "low", "medium", "high", "critical"]
RETRY_AFTER = [timedelta(seconds=s) for s in (30, 120, 600, 1800, 3600)]
MAX_ATTEMPTS = len(RETRY_AFTER) + 1
SEND_LEASE = timedelta(minutes=2)
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
SLACK_API = "https://slack.com/api"
SIGNATURE_WINDOW = 300  # seconds: older Slack requests are refused (replays)
TEAMS_HOSTS = (".webhook.office.com", ".logic.azure.com", ".powerplatform.com")
# Tests replace it with a mock transport.
transport: Optional[httpx.AsyncBaseTransport] = None
_pending: set = set()


class ChatError(ValueError):
    """The channel cannot be saved or reached; the message says why, for people."""


def _channels():
    return scoped(get_database(), "chat_channels")


def _messages():
    return scoped(get_database(), "chat_messages")


async def ensure_indexes() -> None:
    await get_database()["chat_messages"].create_index([("status", 1), ("next_attempt_at", 1)])
    await get_database()["chat_messages"].create_index("created_at", expireAfterSeconds=7 * 24 * 3600)
    await get_database()["chat_channels"].create_index("tenant_id")


def _context(channel_id: Any) -> str:
    return f"chat:{channel_id}"


def _secrets(channel: Dict[str, Any]) -> Dict[str, str]:
    return json.loads(crypto.decrypt(channel["secrets"], _context(channel["_id"])))


def interactions_url(channel_id: str) -> Optional[str]:
    base = settings.GATEWAY_URL.rstrip("/") if settings.GATEWAY_URL else ""
    return f"{base}{settings.API_PREFIX}/chat/slack/{channel_id}/interactions"


def public(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        "id": str(doc["_id"]), "name": doc["name"], "kind": doc["kind"], "events": doc.get("events") or [],
        "min_alert_severity": doc.get("min_alert_severity", "high"), "enabled": doc.get("enabled", True),
        "slack_channel": doc.get("slack_channel"), "last_status": doc.get("last_status"), "last_error": doc.get("last_error"),
        "last_sent_at": doc.get("last_sent_at"), "created_at": doc.get("created_at"), "interactions_url": None,
    }
    if doc["kind"] == "slack_app":
        out["interactions_url"] = interactions_url(str(doc["_id"]))
    return out


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, transport=transport)


async def _check_webhook_url(kind: str, url: str) -> None:
    from core.services import webhooks

    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if kind == "slack_webhook" and (host != "hooks.slack.com" or not parsed.path.startswith(("/services/", "/triggers/", "/workflows/"))):
        raise ChatError("That is not a Slack incoming webhook URL (https://hooks.slack.com/services/...)")
    if kind == "teams" and not host.endswith(TEAMS_HOSTS):
        raise ChatError("That is not a Teams Workflows webhook URL: in Teams, add the Workflows template "
                        "\"Post to a channel when a webhook request is received\" and copy its URL")
    try:
        await webhooks.check_url(url.strip())
    except webhooks.WebhookError as e:
        raise ChatError(str(e))


async def _slack_api(method: str, token: str, payload: Optional[Dict[str, Any]] = None, query: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    async with _client() as client:
        if payload is None:
            response = await client.get(f"{SLACK_API}/{method}", params=query, headers={"Authorization": f"Bearer {token}"})
        else:
            response = await client.post(f"{SLACK_API}/{method}", json=payload, headers={"Authorization": f"Bearer {token}"})
    try:
        body = response.json()
    except ValueError:
        raise ChatError(f"Slack answered {response.status_code}")
    if not body.get("ok"):
        raise ChatError(f"Slack refused: {body.get('error', 'unknown error')}")
    return body


# ---------------------------------------------------------------------------- Channels

def _clean_events(events: List[str]) -> List[str]:
    unknown = sorted(set(events) - set(EVENTS))
    if unknown:
        raise ChatError(f"Not events a channel can have: {', '.join(unknown)}")
    if not events:
        raise ChatError("Choose at least one event")
    return [e for e in EVENTS if e in events]


async def create(body: Dict[str, Any], created_by: Dict[str, Any]) -> Dict[str, Any]:
    kind = body.get("kind")
    if kind not in KINDS:
        raise ChatError("Choose Slack (webhook), Slack (app) or Microsoft Teams")
    if body.get("min_alert_severity", "high") not in SEVERITIES:
        raise ChatError("Choose a severity: info, low, medium, high or critical")
    secrets: Dict[str, str] = {}
    if kind in ("slack_webhook", "teams"):
        url = (body.get("webhook_url") or "").strip()
        await _check_webhook_url(kind, url)
        secrets["url"] = url
    else:
        token, signing, channel = (body.get("bot_token") or "").strip(), (body.get("signing_secret") or "").strip(), (body.get("slack_channel") or "").strip()
        if not token.startswith("xoxb-") or not signing or not channel:
            raise ChatError("A Slack app needs its bot token (xoxb-...), its signing secret and the channel's id (C...)")
        await _slack_api("auth.test", token, {})  # a wrong token is found now, not at the first alert
        secrets.update(bot_token=token, signing_secret=signing)
    doc_id = ObjectId()
    doc = {
        "_id": doc_id, "name": (body.get("name") or "").strip() or kind, "kind": kind, "events": _clean_events(body.get("events") or []),
        "min_alert_severity": body.get("min_alert_severity", "high"), "enabled": True, "slack_channel": (body.get("slack_channel") or "").strip() or None,
        "secrets": crypto.encrypt(json.dumps(secrets), _context(doc_id)), "created_at": utcnow(), "created_by": created_by, "last_status": None,
    }
    await _channels().insert_one(doc)
    return public(doc)


async def list_channels() -> List[Dict[str, Any]]:
    return [public(d) async for d in _channels().find().sort("created_at", 1)]


async def _get(channel_id: str) -> Dict[str, Any]:
    doc = await _channels().find_one({"_id": ObjectId(channel_id)}) if ObjectId.is_valid(channel_id) else None
    if not doc:
        raise LookupError("Channel not found")
    return doc


async def update(channel_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
    doc = await _get(channel_id)
    fields: Dict[str, Any] = {}
    if changes.get("name") is not None:
        fields["name"] = changes["name"].strip() or doc["name"]
    if changes.get("events") is not None:
        fields["events"] = _clean_events(changes["events"])
    if changes.get("min_alert_severity") is not None:
        if changes["min_alert_severity"] not in SEVERITIES:
            raise ChatError("Choose a severity: info, low, medium, high or critical")
        fields["min_alert_severity"] = changes["min_alert_severity"]
    if changes.get("enabled") is not None:
        fields["enabled"] = bool(changes["enabled"])
    if fields:
        await _channels().update_one({"_id": doc["_id"]}, {"$set": fields})
    return public({**doc, **fields})


async def delete(channel_id: str) -> None:
    doc = await _get(channel_id)
    await _channels().delete_one({"_id": doc["_id"]})
    await _messages().delete_many({"channel_id": channel_id, "status": {"$in": ["queued", "sending"]}})


async def messages_of(channel_id: str, limit: int = 30) -> List[Dict[str, Any]]:
    found = await _messages().find({"channel_id": channel_id}).sort("created_at", -1).limit(limit).to_list(None)
    return [{"id": str(m["_id"]), "event": m["event"], "status": m["status"], "attempts": m.get("attempts", 0), "error": m.get("error"),
             "created_at": m["created_at"], "sent_at": m.get("sent_at")} for m in found]


# ---------------------------------------------------------------------------- Messages

def _message(event: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """What to say: a title, lines, facts, a link, and the action to decide on (if any). None: nothing to say."""
    from core.services.inbox import _action_label

    link = data.get("url") or settings.DASHBOARD_URL
    if event == "alert.created":
        return {"title": f"New {data.get('severity', '')} alert: {data.get('title')}", "facts": [("Severity", str(data.get("severity", "")).capitalize()),
                ("Status", str(data.get("status", "open")).replace("_", " "))], "link": link, "button": "Open the alert", "severity": data.get("severity")}
    if event == "case.created":
        return {"title": f"New {data.get('priority', '')} priority case: {data.get('title')}", "facts": [("Priority", str(data.get("priority", "")).capitalize())],
                "link": link, "button": "Open the case", "severity": data.get("priority")}
    if event == "action.approval_requested":
        return {"title": f"Waiting for a decision: {_action_label(data)}", "lines": [data["reason"]] if data.get("reason") else [],
                "facts": [("Protected account", "yes: administrators decide")] if data.get("protected") else [], "link": link,
                "button": "Review in UTDRS", "decide": data.get("id"), "severity": "high"}
    if event == "action.failed":
        return {"title": f"Failed: {_action_label(data)}", "lines": [data["error"]] if data.get("error") else [], "link": link, "button": "Open in UTDRS",
                "severity": "high"}
    if event == "report.ready":
        return {"title": f"Report ready: {data.get('title')}", "lines": [data["headline"]] if data.get("headline") else [], "link": link, "button": "Read the report"}
    if event == "connector.unhealthy":
        errors = data.get("errors") or []
        return {"title": f"{data.get('connector')} stopped bringing data in", "lines": [str(e) for e in errors][:3] if isinstance(errors, list) else [str(errors)],
                "link": link, "button": "Check the connector", "severity": "high"}
    if event == "test":
        return {"title": "UTDRS is connected", "lines": ["Alerts and decisions you chose will appear here."], "link": settings.DASHBOARD_URL, "button": "Open UTDRS"}
    return None


def slack_blocks(message: Dict[str, Any], interactive: bool) -> Dict[str, Any]:
    text = f"*{message['title']}*"
    lines = message.get("lines") or []
    if lines:
        text += "\n" + "\n".join(lines)
    blocks: List[Dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}]
    if message.get("facts"):
        blocks.append({"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{k}*\n{v}"} for k, v in message["facts"]][:10]})
    buttons: List[Dict[str, Any]] = []
    if interactive and message.get("decide"):
        buttons += [
            {"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "style": "primary", "action_id": "utdrs_approve", "value": message["decide"],
             "confirm": {"title": {"type": "plain_text", "text": "Approve this action?"}, "text": {"type": "plain_text", "text": message["title"][:280]},
                         "confirm": {"type": "plain_text", "text": "Approve"}, "deny": {"type": "plain_text", "text": "Cancel"}}},
            {"type": "button", "text": {"type": "plain_text", "text": "Reject"}, "style": "danger", "action_id": "utdrs_reject", "value": message["decide"]},
        ]
    if message.get("link"):
        buttons.append({"type": "button", "text": {"type": "plain_text", "text": message.get("button", "Open in UTDRS")}, "url": message["link"], "action_id": "utdrs_open"})
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    return {"text": message["title"], "blocks": blocks}


def teams_card(message: Dict[str, Any]) -> Dict[str, Any]:
    urgent = message.get("severity") in ("critical", "high")
    body: List[Dict[str, Any]] = [{"type": "TextBlock", "text": message["title"], "weight": "Bolder", "size": "Medium", "wrap": True,
                                   **({"color": "Attention"} if urgent else {})}]
    body += [{"type": "TextBlock", "text": line, "wrap": True} for line in message.get("lines") or []]
    if message.get("facts"):
        body.append({"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in message["facts"]]})
    actions = [{"type": "Action.OpenUrl", "title": message.get("button", "Open in UTDRS"), "url": message["link"]}] if message.get("link") else []
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body, "actions": actions}}]}


def _wants(channel: Dict[str, Any], event: str, data: Dict[str, Any]) -> bool:
    if not channel.get("enabled", True) or event not in (channel.get("events") or []):
        return False
    if event == "alert.created":
        severity = data.get("severity") if data.get("severity") in SEVERITIES else "info"
        return SEVERITIES.index(severity) >= SEVERITIES.index(channel.get("min_alert_severity", "high"))
    return True


async def _enqueue(channel: Dict[str, Any], event: str, message: Dict[str, Any]) -> None:
    now = utcnow()
    await _messages().insert_one({"channel_id": str(channel["_id"]), "event": event, "message": message, "status": "queued", "attempts": 0,
                                  "next_attempt_at": now, "created_at": now, "error": None})


async def from_event(event: str, data: Dict[str, Any]) -> None:
    """Queue what this event says for every channel of the current organisation that wants it. Never raises."""
    try:
        if not current_tenant_or_none():
            return
        if event == "action.completed":
            if data.get("status") != "failed":
                return
            event = "action.failed"
        message = _message(event, data)
        if not message:
            return
        async for channel in _channels().find({"enabled": True, "events": event}):
            if _wants(channel, event, data):
                await _enqueue(channel, event, message)
    except Exception as e:
        logger.error(f"Could not queue {event} for chat: {e}")


async def send_test(channel_id: str) -> None:
    channel = await _get(channel_id)
    await _send(channel, _message("test", {}) or {})


async def _send(channel: Dict[str, Any], message: Dict[str, Any]) -> None:
    secrets = _secrets(channel)
    if channel["kind"] == "slack_app":
        await _slack_api("chat.postMessage", secrets["bot_token"], {"channel": channel["slack_channel"], **slack_blocks(message, interactive=True)})
        return
    body = slack_blocks(message, interactive=False) if channel["kind"] == "slack_webhook" else teams_card(message)
    await _check_webhook_url(channel["kind"], secrets["url"])  # again: DNS may have changed
    async with _client() as client:
        response = await client.post(secrets["url"], json=body, headers={"User-Agent": "UTDRS-Chat/1"})
    if not response.is_success:
        raise ChatError(f"{'Slack' if channel['kind'] == 'slack_webhook' else 'Teams'} answered {response.status_code}: {response.text[:200]}")


async def deliver_due(limit: int = 100) -> int:
    """Send what is due, for every organisation. Returns how many were sent."""
    collection = get_database()["chat_messages"]
    sent = 0
    for _ in range(limit):
        now = utcnow()
        claimed = await collection.find_one_and_update(
            {"$or": [{"status": "queued", "next_attempt_at": {"$lte": now}}, {"status": "sending", "lease_until": {"$lte": now}}]},
            {"$set": {"status": "sending", "lease_until": now + SEND_LEASE}, "$inc": {"attempts": 1}},
            sort=[("next_attempt_at", 1)], return_document=ReturnDocument.AFTER,
        )
        if not claimed:
            break
        with tenant_context(claimed["tenant_id"]):
            channel = await _channels().find_one({"_id": ObjectId(claimed["channel_id"])})
            try:
                if not channel:
                    raise ChatError("The channel was deleted")
                await _send(channel, claimed["message"])
            except Exception as e:
                attempts = claimed["attempts"]
                done = attempts >= MAX_ATTEMPTS or not channel
                reason = str(e) if isinstance(e, (ChatError, crypto.DecryptionFailed)) else f"{e.__class__.__name__}: {e}"
                await collection.update_one({"_id": claimed["_id"]}, {"$set": {"status": "failed" if done else "queued", "error": reason[:300],
                                                                               "next_attempt_at": now if done else now + RETRY_AFTER[attempts - 1]}})
                if channel:
                    await _channels().update_one({"_id": channel["_id"]}, {"$set": {"last_status": "failing", "last_error": reason[:300]}})
                continue
            await collection.update_one({"_id": claimed["_id"]}, {"$set": {"status": "sent", "sent_at": utcnow(), "error": None}})
            await _channels().update_one({"_id": channel["_id"]}, {"$set": {"last_status": "ok", "last_error": None, "last_sent_at": utcnow()}})
            sent += 1
    return sent


async def deliver_periodically() -> None:
    from core.services import heartbeat

    while True:
        error = None
        try:
            await deliver_due()
        except Exception as e:  # never let the loop die
            logger.error(f"Chat delivery failed: {e}")
            error = e
        await heartbeat.beat("chat_delivery", settings.CHAT_INTERVAL_SECONDS, error)
        await asyncio.sleep(settings.CHAT_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------- Deciding from Slack

def verify_slack(signing_secret: str, timestamp: str, body: bytes, signature: str, now: Optional[float] = None) -> bool:
    """Slack's request signature (v0): HMAC-SHA256 of "v0:<timestamp>:<body>", and a recent timestamp."""
    try:
        if abs((now if now is not None else time.time()) - int(timestamp)) > SIGNATURE_WINDOW:
            return False
    except (TypeError, ValueError):
        return False
    expected = "v0=" + hmac.new(signing_secret.encode(), f"v0:{timestamp}:".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


async def slack_interaction(channel_id: str, timestamp: str, signature: str, body: bytes) -> bool:
    """
    A click in Slack. False when the request is not genuinely Slack's for this channel (the caller
    answers 401). Otherwise the decision is made in the background, and Slack is told how it went.
    """
    if not ObjectId.is_valid(channel_id):
        return False
    channel = await get_database()["chat_channels"].find_one({"_id": ObjectId(channel_id), "kind": "slack_app"})
    if not channel or not channel.get("enabled", True):
        return False
    secrets = _secrets(channel)
    if not verify_slack(secrets["signing_secret"], timestamp, body, signature):
        return False
    try:
        payload = json.loads(parse_qs(body.decode()).get("payload", ["{}"])[0])
    except (ValueError, UnicodeDecodeError):
        return True  # genuine, but nothing we understand: ignore
    action = next((a for a in payload.get("actions") or [] if a.get("action_id") in ("utdrs_approve", "utdrs_reject")), None)
    if payload.get("type") != "block_actions" or not action:
        return True
    task = asyncio.create_task(_decide(channel, secrets["bot_token"], payload, action))
    _pending.add(task)
    task.add_done_callback(_pending.discard)
    return True


async def idle() -> None:
    """Wait for decisions made from Slack to finish (shutdown, tests)."""
    while _pending:
        await asyncio.gather(*list(_pending), return_exceptions=True)


async def _reply(response_url: Optional[str], text: str, replace: bool) -> None:
    if not response_url or urlparse(response_url).hostname not in ("hooks.slack.com",):
        return
    try:
        async with _client() as client:
            await client.post(response_url, json={"text": text, "replace_original": replace, "response_type": "ephemeral" if not replace else "in_channel"})
    except Exception as e:
        logger.warning(f"Could not answer Slack: {e}")


async def _decide(channel: Dict[str, Any], token: str, payload: Dict[str, Any], action: Dict[str, Any]) -> None:
    from core.services import audit, response_actions, roles

    approve = action["action_id"] == "utdrs_approve"
    action_id = str(action.get("value") or "")
    response_url = payload.get("response_url")
    with tenant_context(channel["tenant_id"]):
        try:
            info = await _slack_api("users.info", token, query={"user": (payload.get("user") or {}).get("id", "")})
            email = ((info.get("user") or {}).get("profile") or {}).get("email", "").strip().lower()
        except ChatError:
            await _reply(response_url, "UTDRS could not tell who you are in Slack: the app needs the users:read.email permission.", False)
            return
        person = await scoped(get_database(), "users").find_one({"email": email, "active": True}) if email else None
        if not person:
            await _reply(response_url, "Your Slack email address is not a UTDRS account in this organisation; decide in UTDRS instead.", False)
            return
        if not await roles.may(person, "response:write"):
            await _reply(response_url, "Your UTDRS role does not let you decide on response actions.", False)
            return
        actor = {"type": "user", "id": str(person["_id"]), "name": person["username"], "role": person.get("role"), "via": "slack"}
        try:
            result = await (response_actions.approve(action_id, actor) if approve else response_actions.reject(action_id, actor, "Rejected from Slack"))
        except response_actions.ActionError as e:
            await _reply(response_url, f"Not done: {e}", False)
            return
        if not result:
            await _reply(response_url, "That action no longer exists.", False)
            return
        await audit.record(f"response.{'approve' if approve else 'reject'}_action", None, actor=actor, target={"type": "action", "id": action_id},
                           details={"via": "slack"})
        outcome = f"{'Approved' if approve else 'Rejected'} by {person['username']} in Slack" + (f": {result.get('status')}" if approve else "")
        await _reply(response_url, outcome, True)

