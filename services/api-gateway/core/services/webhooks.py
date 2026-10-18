"""
Webhooks: UTDRS tells other systems what happens, as it happens.

An organisation registers an HTTPS endpoint and the events it wants. Each event is queued
once per endpoint and sent by a background loop, retried with growing waits for a day,
and every attempt is in the delivery log, which can be sent again by hand.

Each request is signed, as Stripe and others do: the `UTDRS-Signature` header holds
`t=<unix time>,v1=<hex HMAC-SHA256 of "<t>.<body>">` with the endpoint's secret, so a
receiver can check it came from UTDRS and is recent (reject old timestamps to stop
replays). The secret is shown once, and stored encrypted.

The URL is the organisation's to choose, so it must not become a way into UTDRS's own
network: addresses that are private, loopback, link-local (cloud metadata), reserved or
multicast are refused when the webhook is saved and again before every send, and
redirects are not followed. WEBHOOK_ALLOW_PRIVATE_ADDRESSES lifts this for a deployment
whose receivers are on its own network.
"""
import asyncio
import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import time
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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

EVENTS = {
    "alert.created": "A new alert (not suppressed ones)",
    "case.created": "A new case",
    "case.updated": "A case's status, priority or owner changed",
    "action.approval_requested": "A response action is waiting for a decision",
    "action.completed": "A response action ran (succeeded or failed)",
    "report.ready": "A monthly report was made",
    "connector.unhealthy": "A connector stopped bringing data in",
    "ping": "A test, sent from the dashboard",
}
RETRY_AFTER = [timedelta(seconds=s) for s in (30, 120, 600, 1800, 3600, 7200, 14400, 28800, 43200)]  # about a day in all
MAX_ATTEMPTS = len(RETRY_AFTER) + 1
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
SEND_LEASE = timedelta(minutes=2)
MAX_RESPONSE_KEPT = 500
USER_AGENT = "UTDRS-Webhooks/1"

# For tests: a transport standing in for the receivers.
transport: Optional[httpx.AsyncBaseTransport] = None


class WebhookError(ValueError):
    """The webhook cannot be saved or sent as it is; the message says why."""


def _webhooks():
    return scoped(get_database(), "webhooks")


def _deliveries():
    return scoped(get_database(), "webhook_deliveries")


async def ensure_indexes() -> None:
    deliveries = get_database()["webhook_deliveries"]
    await deliveries.create_index([("status", 1), ("next_attempt_at", 1)])
    await deliveries.create_index([("tenant_id", 1), ("webhook_id", 1), ("created_at", -1)])


# ---------------------------------------------------------------------------
# Where UTDRS may send

def _refused_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


async def check_url(url: str) -> None:
    """Refuse URLs that are not HTTPS, or that lead into a private network."""
    parsed = urlparse(url)
    if parsed.scheme != "https" and not (settings.WEBHOOK_ALLOW_PRIVATE_ADDRESSES and parsed.scheme == "http"):
        raise WebhookError("Webhook URLs must use HTTPS")
    if not parsed.hostname:
        raise WebhookError("That is not a URL")
    if parsed.username or parsed.password:
        raise WebhookError("Put credentials in the receiver's checks of the signature, not in the URL")
    if settings.WEBHOOK_ALLOW_PRIVATE_ADDRESSES:
        return
    try:
        found = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise WebhookError(f"{parsed.hostname} cannot be found")
    if any(_refused_address(info[4][0]) for info in found):
        raise WebhookError(f"{parsed.hostname} is a private or internal address; UTDRS only sends to public ones")


# ---------------------------------------------------------------------------
# Webhooks

def _context(webhook_id: Any) -> str:
    return f"webhook:{webhook_id}"


def sign(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def _new_secret() -> str:
    return f"whsec_{secrets.token_urlsafe(32)}"


async def create(data: Dict[str, Any], actor: Dict[str, Any]) -> Dict[str, Any]:
    if not crypto.available():
        raise WebhookError("Webhooks need ENCRYPTION_KEY set on the gateway, to keep their signing secrets")
    await check_url(data["url"])
    now = utcnow()
    webhook_id = ObjectId()
    secret = _new_secret()
    doc = {
        "_id": webhook_id, "name": data["name"], "url": data["url"], "events": sorted(set(data["events"])), "enabled": True,
        "secret": crypto.encrypt(secret, _context(webhook_id)), "created_by": actor, "created_at": now, "updated_at": now,
        "last_delivery_at": None, "last_status": None,
    }
    await _webhooks().insert_one(doc)
    return {**doc, "signing_secret": secret}


async def list_webhooks() -> List[Dict[str, Any]]:
    return await _webhooks().find({}, {"secret": 0}).sort("created_at", -1).to_list(100)


async def get(webhook_id: str) -> Optional[Dict[str, Any]]:
    return await _webhooks().find_one({"_id": ObjectId(webhook_id)}, {"secret": 0}) if ObjectId.is_valid(webhook_id) else None


async def update(webhook_id: str, changes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(webhook_id):
        return None
    if "url" in changes:
        await check_url(changes["url"])
    if "events" in changes:
        changes["events"] = sorted(set(changes["events"]))
    return await _webhooks().find_one_and_update(
        {"_id": ObjectId(webhook_id)}, {"$set": {**changes, "updated_at": utcnow()}}, projection={"secret": 0}, return_document=ReturnDocument.AFTER
    )


async def rotate_secret(webhook_id: str) -> Optional[str]:
    if not ObjectId.is_valid(webhook_id):
        return None
    secret = _new_secret()
    result = await _webhooks().update_one({"_id": ObjectId(webhook_id)}, {"$set": {"secret": crypto.encrypt(secret, _context(webhook_id)), "updated_at": utcnow()}})
    return secret if result.matched_count else None


async def delete(webhook_id: str) -> bool:
    if not ObjectId.is_valid(webhook_id):
        return False
    deleted = (await _webhooks().delete_one({"_id": ObjectId(webhook_id)})).deleted_count
    if deleted:
        await _deliveries().delete_many({"webhook_id": webhook_id, "status": {"$in": ["queued", "sending"]}})
    return bool(deleted)


# ---------------------------------------------------------------------------
# Events

def _link(path: str) -> str:
    return settings.DASHBOARD_URL.rstrip("/") + path


def _json(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


async def emit(event: str, data: Dict[str, Any], only: Optional[str] = None) -> int:
    """Queue `event` for every enabled webhook of the current organisation that wants it. Never raises."""
    try:
        if current_tenant_or_none() is None:
            return 0
        query: Dict[str, Any] = {"enabled": True, "events": {"$in": [event, "*"]}}
        if only:
            query = {"_id": ObjectId(only)}
        now = utcnow()
        queued = 0
        async for webhook in _webhooks().find(query, {"_id": 1}):
            delivery_id = f"evt_{uuid.uuid4().hex}"
            payload = {"id": delivery_id, "type": event, "created_at": now.isoformat(), "data": _json(data)}
            await _deliveries().insert_one({
                "_id": delivery_id, "webhook_id": str(webhook["_id"]), "event": event, "payload": payload, "status": "queued",
                "attempts": 0, "next_attempt_at": now, "created_at": now, "delivered_at": None, "response_status": None, "error": None,
            })
            queued += 1
        return queued
    except Exception as e:
        logger.error(f"Could not queue webhook event {event}: {e}")
        return 0


def alert_data(alert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(alert["_id"]), "title": alert.get("title"), "severity": alert.get("severity"), "status": alert.get("status"),
        "case_id": alert.get("case_id"), "tags": alert.get("tags") or [], "created_at": alert.get("created_at"), "url": _link(f"/alerts/{alert['_id']}"),
    }


def case_data(case: Dict[str, Any], changes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = {
        "id": str(case["_id"]), "title": case.get("title"), "status": case.get("status"), "priority": case.get("priority"),
        "owner_id": case.get("owner_id"), "due_at": case.get("due_at"), "url": _link(f"/cases/{case['_id']}"),
    }
    if changes:
        out["changes"] = changes
    return out


def action_data(action: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(action["_id"]), "action": action.get("action"), "target": action.get("target"), "status": action.get("status"),
        "mode": action.get("mode"), "reason": action.get("reason"), "case_id": action.get("case_id"), "error": action.get("error"),
        "summary": (action.get("result") or {}).get("summary"), "url": _link(f"/cases/{action['case_id']}" if action.get("case_id") else "/response"),
    }


# ---------------------------------------------------------------------------
# Sending

async def _send(delivery: Dict[str, Any]) -> None:
    """One attempt. Raises with the reason when it does not succeed."""
    webhook = await get_database()["webhooks"].find_one({"_id": ObjectId(delivery["webhook_id"])})
    if not webhook:
        raise WebhookError("The webhook was deleted")
    await check_url(webhook["url"])  # again: DNS may have changed since it was saved
    secret = crypto.decrypt(webhook["secret"], _context(webhook["_id"]))
    body = json.dumps(delivery["payload"], separators=(",", ":")).encode()
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json", "User-Agent": USER_AGENT, "UTDRS-Event": delivery["event"],
        "UTDRS-Delivery": delivery["_id"], "UTDRS-Signature": sign(secret, timestamp, body),
    }
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, transport=transport) as client:
        response = await client.post(webhook["url"], content=body, headers=headers)
    delivery["response_status"] = response.status_code
    if not response.is_success:
        raise WebhookError(f"The receiver answered {response.status_code}: {response.text[:MAX_RESPONSE_KEPT]}")


async def deliver_due(limit: int = 100) -> int:
    """Send what is due for every organisation. Returns how many were delivered."""
    deliveries = get_database()["webhook_deliveries"]
    sent = 0
    for _ in range(limit):
        now = utcnow()
        claimed = await deliveries.find_one_and_update(
            {"$or": [{"status": "queued", "next_attempt_at": {"$lte": now}}, {"status": "sending", "lease_until": {"$lte": now}}]},
            {"$set": {"status": "sending", "lease_until": now + SEND_LEASE}, "$inc": {"attempts": 1}},
            sort=[("next_attempt_at", 1)], return_document=ReturnDocument.AFTER,
        )
        if not claimed:
            break
        with tenant_context(claimed["tenant_id"]):
            try:
                await _send(claimed)
            except Exception as e:
                attempts = claimed["attempts"]
                done = attempts >= MAX_ATTEMPTS or "deleted" in str(e)
                reason = str(e) if isinstance(e, (WebhookError, crypto.DecryptionFailed)) else f"{e.__class__.__name__}: {e}"
                await deliveries.update_one({"_id": claimed["_id"]}, {"$set": {
                    "status": "failed" if done else "queued", "error": reason[:MAX_RESPONSE_KEPT], "response_status": claimed.get("response_status"),
                    "next_attempt_at": now if done else now + RETRY_AFTER[attempts - 1],
                }})
                await get_database()["webhooks"].update_one({"_id": ObjectId(claimed["webhook_id"])}, {"$set": {"last_status": "failing", "last_delivery_at": now}})
                continue
            await deliveries.update_one({"_id": claimed["_id"]}, {"$set": {
                "status": "delivered", "delivered_at": utcnow(), "error": None, "response_status": claimed.get("response_status"),
            }})
            await get_database()["webhooks"].update_one({"_id": ObjectId(claimed["webhook_id"])}, {"$set": {"last_status": "ok", "last_delivery_at": now}})
            sent += 1
    return sent


async def deliver_periodically() -> None:
    while True:
        try:
            await deliver_due()
        except Exception as e:  # never let the loop die
            logger.error(f"Webhook delivery failed: {e}")
        await asyncio.sleep(settings.WEBHOOK_INTERVAL_SECONDS)


async def deliveries_of(webhook_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    return await _deliveries().find({"webhook_id": webhook_id}, {"tenant_id": 0}).sort("created_at", -1).limit(limit).to_list(limit)


async def redeliver(delivery_id: str) -> Optional[Dict[str, Any]]:
    """Send a delivery again, now: as a new attempt of the same event (same id, so receivers can de-duplicate)."""
    return await _deliveries().find_one_and_update(
        {"_id": delivery_id, "status": {"$in": ["failed", "delivered"]}},
        {"$set": {"status": "queued", "next_attempt_at": utcnow(), "attempts": 0, "error": None}},
        projection={"tenant_id": 0}, return_document=ReturnDocument.AFTER,
    )
