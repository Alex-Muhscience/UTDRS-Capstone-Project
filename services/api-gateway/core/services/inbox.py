"""
The notifications centre: each person's inbox in the dashboard.

What deserves someone's attention lands here, for the people whose role lets them act on or
see it: serious new alerts and cases, response actions waiting for a decision, actions that
failed (and the requester's own, when done), new reports and failing connectors (for
administrators), and alerts and cases assigned to them. Most come from the same events as
webhooks (webhooks.emit calls `from_event`); assignments come from where they are made, which
knows who made them, so nobody is told of what they did themselves.

Items are kept for 90 days. Email notifications (core/services/notifications.py) are separate
and follow each person's preferences; the inbox has everything relevant.
"""
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional

from bson import ObjectId

from core.database.connection import get_database
from core.tenancy import current_tenant_or_none, scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "inbox"
KEEP = timedelta(days=90)
SERIOUS_ALERTS = {"critical", "high"}
SERIOUS_CASES = {"critical", "high"}


def _inbox():
    return scoped(get_database(), COLLECTION)


async def ensure_indexes() -> None:
    collection = get_database()[COLLECTION]
    await collection.create_index("created_at", expireAfterSeconds=int(KEEP.total_seconds()))
    await collection.create_index([("tenant_id", 1), ("user_id", 1), ("created_at", -1)])


def _path(url: Optional[str]) -> Optional[str]:
    """The dashboard path of a link (webhook payloads carry full URLs)."""
    if not url:
        return None
    marker = url.find("/", url.find("//") + 2) if "//" in url else 0
    return url[marker:] if marker >= 0 else url


async def _recipients(permission: str, only_admins: bool = False, exclude: Iterable[str] = ()) -> List[str]:
    from core.services import roles

    query: Dict[str, Any] = {"active": True}
    if only_admins:
        query["role"] = "admin"
    people = await scoped(get_database(), "users").find(query, {"role": 1, "custom_role_id": 1}).to_list(1000)
    skip = set(exclude)
    return [str(p["_id"]) for p in people if str(p["_id"]) not in skip and await roles.may(p, permission)]


async def add(user_ids: List[str], kind: str, title: str, body: str = "", link: Optional[str] = None,
              severity: Optional[str] = None, target: Optional[Dict[str, Any]] = None) -> int:
    """Put an item in these people's inboxes (in the current organisation), and tell their dashboards."""
    if not user_ids or not current_tenant_or_none():
        return 0
    now = utcnow()
    docs = [{"user_id": user_id, "kind": kind, "title": title[:300], "body": body[:1000], "link": link, "severity": severity,
             "target": target, "created_at": now, "read_at": None} for user_id in dict.fromkeys(user_ids)]
    await _inbox().insert_many(docs)
    from core.services import live

    await live.publish("inbox.created", {"users": list(dict.fromkeys(user_ids))})
    return len(docs)


async def from_event(event: str, data: Dict[str, Any]) -> None:
    """The inbox items an event makes, if any. Never raises."""
    try:
        await _from_event(event, data)
    except Exception as e:
        logger.error(f"Could not put {event} in inboxes: {e}")


async def _from_event(event: str, data: Dict[str, Any]) -> None:
    link = _path(data.get("url"))
    if event == "alert.created" and data.get("severity") in SERIOUS_ALERTS:
        await add(await _recipients("alerts:read"), "alert", f"New {data['severity']} alert: {data.get('title')}", link=link,
                  severity=data["severity"], target={"type": "alert", "id": data.get("id")})
    elif event == "case.created" and data.get("priority") in SERIOUS_CASES:
        await add(await _recipients("cases:read"), "case", f"New {data['priority']} priority case: {data.get('title')}", link=link,
                  severity=data["priority"], target={"type": "case", "id": data.get("id")})
    elif event == "action.approval_requested":
        what = _action_label(data)
        await add(await _recipients("response:write", only_admins=bool(data.get("protected"))), "approval",
                  f"Waiting for a decision: {what}", data.get("reason") or "", link=link, severity="high", target={"type": "action", "id": data.get("id")})
    elif event == "action.completed":
        what = _action_label(data)
        requester = (data.get("requested_by") or {})
        requester_id = requester.get("id") if requester.get("type") == "user" else None
        if data.get("status") == "failed":
            await add(await _recipients("response:read"), "action_failed", f"Failed: {what}", data.get("error") or "", link=link,
                      severity="high", target={"type": "action", "id": data.get("id")})
        elif requester_id:
            await add([requester_id], "action_done", f"Done: {what}", data.get("summary") or "", link=link, target={"type": "action", "id": data.get("id")})
    elif event == "report.ready":
        await add(await _recipients("reports:read", only_admins=True), "report", f"Report ready: {data.get('title')}", data.get("headline") or "",
                  link=link, target={"type": "report", "id": data.get("id")})
    elif event == "connector.unhealthy":
        name = {"microsoft-365": "Microsoft 365", "google-workspace": "Google Workspace"}.get(data.get("connector"), str(data.get("connector")))
        errors = data.get("errors") or []
        await add(await _recipients("alerts:read", only_admins=True), "connector", f"{name} stopped bringing data in",
                  "; ".join(str(e) for e in errors)[:500] if isinstance(errors, list) else str(errors), link=link or "/connectors", severity="high",
                  target={"type": "connector", "id": data.get("connector")})


def _action_label(data: Dict[str, Any]) -> str:
    from core.services.response_actions import CATALOGUE

    entry = CATALOGUE.get(data.get("action") or "")
    target = data.get("target") or {}
    on = "the case" if target.get("type") == "case" else target.get("value")
    return f"{entry.label if entry else data.get('action')}{f', for {on}' if on else ''}"


async def assigned(kind: str, item_id: str, title: str, to_user: Optional[str], by: Dict[str, Any]) -> None:
    """Tell someone an alert or case is now theirs, unless they took it themselves. Never raises."""
    try:
        if not to_user or to_user == by.get("id"):
            return
        await add([to_user], f"{kind}_assigned", f"{by.get('name') or 'Someone'} assigned you a{'n' if kind == 'alert' else ''} {kind}: {title}",
                  link=f"/{kind}s/{item_id}", target={"type": kind, "id": item_id})
    except Exception as e:
        logger.error(f"Could not tell {to_user} of their {kind}: {e}")


async def list_for(user_id: str, unread_only: bool = False, before: Optional[str] = None, limit: int = 30) -> Dict[str, Any]:
    query: Dict[str, Any] = {"user_id": user_id}
    if unread_only:
        query["read_at"] = None
    if before and ObjectId.is_valid(before):
        query["_id"] = {"$lt": ObjectId(before)}
    found = await _inbox().find(query).sort("_id", -1).limit(limit + 1).to_list(None)
    items = [{"id": str(d["_id"]), "kind": d["kind"], "title": d["title"], "body": d.get("body") or "", "link": d.get("link"),
              "severity": d.get("severity"), "target": d.get("target"), "created_at": d["created_at"], "read": d.get("read_at") is not None}
             for d in found[:limit]]
    return {"items": items, "has_more": len(found) > limit, "unread": await unread(user_id)}


async def unread(user_id: str) -> int:
    return await _inbox().count_documents({"user_id": user_id, "read_at": None})


async def mark_read(user_id: str, item_ids: Optional[List[str]] = None) -> int:
    """Mark these items (or all) read; only the person's own."""
    query: Dict[str, Any] = {"user_id": user_id, "read_at": None}
    if item_ids is not None:
        query["_id"] = {"$in": [ObjectId(i) for i in item_ids if ObjectId.is_valid(i)]}
    return (await _inbox().update_many(query, {"$set": {"read_at": utcnow()}})).modified_count
