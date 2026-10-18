"""
Email notifications: new cases, approvals needed and actions taken, to the people who want them.

Something that happens (a case opens, an action waits for approval or finishes) puts one
message per interested person in the `notifications` outbox. A background loop sends
what is due over SMTP, retrying failures with growing waits, so a mail server that is
down for a while loses nothing. Every message stays in the outbox as the delivery log.

Each person chooses (per-user preferences, `notify` on their user record):
- email: whether to get email at all;
- new_cases: the lowest priority of new case to hear about, or "off";
- approvals: actions waiting for a decision they can make;
- actions: actions that ran: "all", "failed" only, or "off".
Nobody is sent more than NOTIFY_MAX_PER_USER_PER_HOUR emails in an hour.
"""
import asyncio
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage
from email.utils import make_msgid
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo import ReturnDocument

from config import settings
from core.database.connection import get_database
from core.services import case_service
from core.tenancy import scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "notifications"
DEFAULTS: Dict[str, Any] = {"email": True, "new_cases": "high", "approvals": True, "actions": "failed"}
RETRY_AFTER = [timedelta(seconds=30), timedelta(minutes=2), timedelta(minutes=10), timedelta(hours=1)]
MAX_ATTEMPTS = len(RETRY_AFTER) + 1
SEND_LEASE = timedelta(minutes=2)  # a send that takes longer is assumed lost, and retried
SMTP_TIMEOUT_SECONDS = 15


def configured() -> bool:
    return bool(settings.SMTP_HOST)


def _outbox():
    return scoped(get_database(), COLLECTION)


def _users():
    return scoped(get_database(), "users")


async def ensure_indexes() -> None:
    outbox = get_database()[COLLECTION]
    await outbox.create_index([("status", 1), ("next_attempt_at", 1)])
    await outbox.create_index([("tenant_id", 1), ("user_id", 1), ("created_at", -1)])
    await outbox.create_index([("tenant_id", 1), ("created_at", -1)])


def preferences_of(user: Dict[str, Any]) -> Dict[str, Any]:
    return {**DEFAULTS, **(user.get("notify") or {})}


async def get_preferences(user_id: str) -> Dict[str, Any]:
    return preferences_of(await _users().find_one({"_id": ObjectId(user_id)}, {"notify": 1}) or {})


async def set_preferences(user_id: str, changes: Dict[str, Any]) -> Dict[str, Any]:
    user = await _users().find_one({"_id": ObjectId(user_id)})
    updated = {**preferences_of(user or {}), **changes}
    await _users().update_one({"_id": ObjectId(user_id)}, {"$set": {"notify": updated}})
    return updated


def _link(path: str) -> str:
    return settings.DASHBOARD_URL.rstrip("/") + path


def _header(value: str) -> str:
    """A header value: one line (a title from an alert must not add headers), not too long."""
    return " ".join(str(value).split())[:200]


async def _enqueue(kind: str, users: List[Dict[str, Any]], subject: str, text: str, link: str, about: Dict[str, Any]) -> int:
    now = utcnow()
    queued = 0
    for user in users:
        if not user.get("email"):
            continue
        status, error = "queued", None
        recent = await _outbox().count_documents({"user_id": str(user["_id"]), "created_at": {"$gte": now - timedelta(hours=1)}})
        if recent >= settings.NOTIFY_MAX_PER_USER_PER_HOUR:
            status, error = "skipped", f"More than {settings.NOTIFY_MAX_PER_USER_PER_HOUR} emails to this person in an hour"
        elif not configured():
            status, error = "skipped", "Email is not configured (SMTP_HOST)"
        await _outbox().insert_one({
            "kind": kind, "user_id": str(user["_id"]), "email": user["email"], "subject": _header(subject),
            "text": f"{text}\n\n{link}\n\n— UTDRS. Choose what you are emailed about in your profile: {_link('/profile')}\n",
            "link": link, "about": about, "status": status, "error": error, "attempts": 0,
            "created_at": now, "next_attempt_at": now, "sent_at": None,
        })
        queued += status == "queued"
    return queued


async def _people(**query) -> List[Dict[str, Any]]:
    return await _users().find({"active": True, **query}).to_list(1000)


async def _safely(coroutine) -> None:
    """Notifying must never break what is being notified about."""
    try:
        await coroutine
    except Exception as e:
        logger.error(f"Could not queue a notification: {e}")


async def case_opened(case: Dict[str, Any], alerts: List[Dict[str, Any]]) -> None:
    await _safely(_case_opened(case, alerts))


async def _case_opened(case: Dict[str, Any], alerts: List[Dict[str, Any]]) -> None:
    order = case_service.PRIORITIES
    wanted = [
        u for u in await _people()
        if preferences_of(u)["email"] and preferences_of(u)["new_cases"] in order
        and order.index(case["priority"]) >= order.index(preferences_of(u)["new_cases"])
    ]
    if not wanted:
        return
    explanation = case_service.explain(case, alerts)
    steps = "\n".join(f"  {n}. {step}" for n, step in enumerate(explanation["next_steps"], 1))
    text = (
        f"A new {case['priority']} priority case: {case['title']}\n\n"
        f"{explanation['what_happened']}\n\n{explanation['why_it_matters']}\n\n"
        f"What to do:\n{steps}\n\nDue by {case['due_at']:%d %b %H:%M} UTC."
    )
    await _enqueue("case_opened", wanted, f"[UTDRS] {case['priority'].capitalize()} case: {case['title']}", text,
                   _link(f"/cases/{case['_id']}"), {"type": "case", "id": str(case["_id"])})


def _target(action: Dict[str, Any]) -> str:
    return "the case" if action["target"]["type"] == "case" else action["target"]["value"]


async def approval_needed(action: Dict[str, Any]) -> None:
    await _safely(_approval_needed(action))


async def _approval_needed(action: Dict[str, Any]) -> None:
    # Only those who can decide: administrators, for a protected account.
    people = await _people(**({"role": "admin"} if action.get("protected") else {}))
    wanted = [u for u in people if preferences_of(u)["email"] and preferences_of(u)["approvals"]]
    if not wanted:
        return
    from core.services.response_actions import CATALOGUE

    label = CATALOGUE[action["action"]].label
    who = f"Playbook \"{action['playbook']['name']}\"" if action.get("playbook") else str(action["requested_by"].get("name") or "Someone")
    verb = "suggests" if action["mode"] == "notify" else "asks to"
    text = f"{who} {verb}: {label}, for {_target(action)}."
    if action.get("reason"):
        text += f"\n\nIt is waiting because: {action['reason']}."
    text += "\n\nApprove or reject it in UTDRS:"
    await _enqueue("approval_needed", wanted, f"[UTDRS] Approval needed: {label} — {_target(action)}", text,
                   _link(f"/cases/{action['case_id']}" if action.get("case_id") else "/response"), {"type": "action", "id": str(action["_id"])})


async def action_finished(action: Dict[str, Any]) -> None:
    await _safely(_action_finished(action))


async def _action_finished(action: Dict[str, Any]) -> None:
    failed = action["status"] == "failed"
    decider = (action.get("decided_by") or {}).get("id")
    wanted = [
        u for u in await _people()
        if preferences_of(u)["email"] and (preferences_of(u)["actions"] == "all" or (failed and preferences_of(u)["actions"] == "failed"))
        and str(u["_id"]) != decider  # who did it knows
    ]
    if not wanted:
        return
    from core.services.response_actions import CATALOGUE

    label = CATALOGUE[action["action"]].label
    outcome = f"failed: {action.get('error')}" if failed else (action.get("result") or {}).get("summary", "done")
    who = f"Playbook \"{action['playbook']['name']}\"" if action.get("playbook") and not decider else str((action.get("decided_by") or action["requested_by"]).get("name") or "Someone")
    await _enqueue(
        "action_finished", wanted, f"[UTDRS] {'Failed' if failed else 'Done'}: {label} — {_target(action)}",
        f"{label}, for {_target(action)}: {outcome}.\n\nStarted by {who}.",
        _link(f"/cases/{action['case_id']}" if action.get("case_id") else "/response"), {"type": "action", "id": str(action["_id"])},
    )


# ---------------------------------------------------------------------------
# Sending

def _message(to: str, subject: str, text: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.MAIL_FROM
    message["To"] = to
    message["Subject"] = _header(subject)
    message["Message-ID"] = make_msgid(domain="utdrs")
    message.set_content(text)
    return message


def _send_now(message: EmailMessage) -> None:
    host, port = settings.SMTP_HOST, settings.SMTP_PORT
    if settings.SMTP_SECURITY == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS, context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS)
    with server:
        if settings.SMTP_SECURITY == "starttls":
            server.starttls(context=ssl.create_default_context())
        if settings.SMTP_USERNAME:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD or "")
        server.send_message(message)


async def send_email(to: str, subject: str, text: str) -> None:
    """Send one email now. Raises when the mail server refuses it or cannot be reached."""
    if not configured():
        raise RuntimeError("Email is not configured (SMTP_HOST)")
    await asyncio.to_thread(_send_now, _message(to, subject, text))


def _reason(error: Exception) -> str:
    if isinstance(error, smtplib.SMTPResponseException):
        message = error.smtp_error.decode("utf-8", "replace") if isinstance(error.smtp_error, bytes) else str(error.smtp_error)
        return f"The mail server refused it: {error.smtp_code} {message}"[:300]
    return f"{error.__class__.__name__}: {error}"[:300]


async def deliver_due(limit: int = 50) -> int:
    """Send what is due in every organisation's outbox. Returns how many were sent."""
    outbox = get_database()[COLLECTION]  # the sender works across organisations
    sent = 0
    for _ in range(limit):
        now = utcnow()
        claimed = await outbox.find_one_and_update(
            {"$or": [{"status": "queued", "next_attempt_at": {"$lte": now}}, {"status": "sending", "lease_until": {"$lte": now}}]},
            {"$set": {"status": "sending", "lease_until": now + SEND_LEASE}, "$inc": {"attempts": 1}},
            sort=[("next_attempt_at", 1)], return_document=ReturnDocument.AFTER,
        )
        if not claimed:
            break
        try:
            await send_email(claimed["email"], claimed["subject"], claimed["text"])
        except Exception as e:
            attempts = claimed["attempts"]
            done = attempts >= MAX_ATTEMPTS
            await outbox.update_one({"_id": claimed["_id"]}, {"$set": {
                "status": "failed" if done else "queued", "error": _reason(e),
                "next_attempt_at": now if done else now + RETRY_AFTER[attempts - 1],
            }})
            logger.warning(f"Email {claimed['_id']} not sent (attempt {attempts}): {_reason(e)}")
            continue
        await outbox.update_one({"_id": claimed["_id"]}, {"$set": {"status": "sent", "sent_at": utcnow(), "error": None}})
        sent += 1
    return sent


async def deliver_periodically() -> None:
    """Run for the life of the process: send what is due every NOTIFY_INTERVAL_SECONDS."""
    while True:
        try:
            if configured():
                await deliver_due()
        except Exception as e:  # never let the loop die
            logger.error(f"Email delivery failed: {e}")
        await asyncio.sleep(settings.NOTIFY_INTERVAL_SECONDS)


async def log(query: Dict[str, Any], limit: int, skip: int) -> List[Dict[str, Any]]:
    cursor = _outbox().find(query, {"text": 0, "tenant_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    return await cursor.to_list(limit)


async def send_test(email: str) -> Optional[str]:
    """Send a test email now. Returns why it could not be sent, or None."""
    try:
        await send_email(email, "[UTDRS] Test email", f"This is a test email from UTDRS, sent to {email}.\n\nEmail notifications work.\n")
    except Exception as e:
        return _reason(e)
    return None
