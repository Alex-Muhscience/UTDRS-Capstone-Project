"""
Data retention: each organisation's data is kept for as long as it chooses, then deleted.

How long each kind of data is kept is set per organisation, within the deployment's
defaults and maximum (RETENTION_*; per plan once billing exists). Every hour, what has
passed its time is deleted, in batches:

- events, by when they were received; except those behind an alert or a case that is
  still open, which are evidence;
- alerts that are closed (resolved, closed, false positive, suppressed), by when they
  last changed; except those in a case that is still open;
- cases that are closed, by when they last changed;
- response actions, except those still waiting for a decision;
- the email log;
- analysts' verdict labels, kept longest because they train the models.

Open work is never deleted, however old. The audit log is not trimmed: its entries are
chained, so removing old ones needs a signed checkpoint first (still to come). Reports
are small and kept.
"""
import asyncio
from datetime import timedelta
from typing import Any, Dict, Set

from bson import ObjectId

from config import settings
from core.database.connection import get_database
from core.services import tenants
from core.tenancy import current_tenant, scoped, tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

KINDS = ["events", "alerts", "cases", "actions", "notifications", "labels"]
OPEN_CASES = ["open", "investigating", "contained"]
OPEN_ALERTS = ["open", "in_progress"]
CLOSED_ALERTS = ["resolved", "closed", "false_positive", "suppressed"]
CLOSED_CASES = ["resolved", "false_positive", "closed"]
BATCH = 5000
MAX_BATCHES = 20  # per kind and run; the next run carries on


def defaults() -> Dict[str, int]:
    return {
        "events": settings.RETENTION_EVENTS_DAYS,
        "alerts": settings.RETENTION_ALERTS_DAYS,
        "cases": settings.RETENTION_ALERTS_DAYS,
        "actions": settings.RETENTION_ALERTS_DAYS,
        "notifications": settings.RETENTION_NOTIFICATIONS_DAYS,
        "labels": settings.RETENTION_LABELS_DAYS,
    }


async def get_settings() -> Dict[str, Any]:
    tenant = await tenants.get(current_tenant()) or {}
    stored = tenant.get("retention") or {}
    return {
        "days": {**defaults(), **(stored.get("days") or {})},
        "defaults": defaults(),
        "max_days": settings.RETENTION_MAX_DAYS,
        "last_run": stored.get("last_run"),
    }


async def update_settings(days: Dict[str, int]) -> Dict[str, Any]:
    too_long = [kind for kind, value in days.items() if value > settings.RETENTION_MAX_DAYS]
    if too_long:
        raise ValueError(f"At most {settings.RETENTION_MAX_DAYS} days on this deployment ({', '.join(too_long)})")
    await get_database()["tenants"].update_one(
        {"_id": ObjectId(current_tenant())}, {"$set": {f"retention.days.{kind}": value for kind, value in days.items()}}
    )
    return await get_settings()


async def _delete(name: str, query: Dict[str, Any]) -> int:
    """Delete what matches, BATCH at a time, so one run never holds the database for long."""
    collection = scoped(get_database(), name)
    deleted = 0
    for _ in range(MAX_BATCHES):
        ids = [d["_id"] for d in await collection.find(query, {"_id": 1}).limit(BATCH).to_list(BATCH)]
        if not ids:
            break
        deleted += (await collection.delete_many({"_id": {"$in": ids}})).deleted_count
        if len(ids) < BATCH:
            break
    return deleted


async def _open_work() -> Dict[str, Set]:
    """The cases and alerts still being worked, and the events behind them: never deleted."""
    database = get_database()
    open_cases = await scoped(database, "cases").find({"status": {"$in": OPEN_CASES}}, {"alert_ids": 1}).to_list(None)
    case_ids = {str(c["_id"]) for c in open_cases}
    alert_ids = {a for c in open_cases for a in c.get("alert_ids") or []}
    open_alerts = await scoped(database, "alerts").find(
        {"$or": [{"status": {"$in": OPEN_ALERTS}}, {"case_id": {"$in": list(case_ids)}}, {"_id": {"$in": [ObjectId(a) for a in alert_ids if ObjectId.is_valid(a)]}}]},
        {"event_ids": 1},
    ).to_list(None)
    event_ids = {ObjectId(e) for a in open_alerts for e in a.get("event_ids") or [] if ObjectId.is_valid(e)}
    return {"cases": case_ids, "alerts": {a["_id"] for a in open_alerts}, "events": event_ids}


async def run(now=None) -> Dict[str, int]:
    """Delete the current organisation's data that has passed its time. Returns how much of each kind."""
    now = now or utcnow()
    days = (await get_settings())["days"]
    cutoff = {kind: now - timedelta(days=days[kind]) for kind in KINDS}
    keep = await _open_work()
    deleted = {
        "events": await _delete("events", {"created_at": {"$lt": cutoff["events"]}, "_id": {"$nin": list(keep["events"])}}),
        "alerts": await _delete("alerts", {
            "status": {"$in": CLOSED_ALERTS}, "updated_at": {"$lt": cutoff["alerts"]},
            "_id": {"$nin": list(keep["alerts"])}, "case_id": {"$nin": list(keep["cases"])},
        }),
        "cases": await _delete("cases", {"status": {"$in": CLOSED_CASES}, "updated_at": {"$lt": cutoff["cases"]}}),
        "actions": await _delete("actions", {"status": {"$ne": "pending"}, "created_at": {"$lt": cutoff["actions"]}}),
        "notifications": await _delete("notifications", {"created_at": {"$lt": cutoff["notifications"]}}),
        "labels": await _delete("labels", {"at": {"$lt": cutoff["labels"]}}),
    }
    await get_database()["tenants"].update_one(
        {"_id": ObjectId(current_tenant())}, {"$set": {"retention.last_run": {"at": now, "deleted": deleted}}}
    )
    if any(deleted.values()):
        logger.info(f"Retention deleted {deleted}")
    return deleted


async def run_all() -> None:
    for tenant_id in await tenants.all_ids():
        with tenant_context(tenant_id):
            try:
                await run()
            except Exception:
                logger.exception("Retention failed for an organisation")


async def run_periodically() -> None:
    """Run for the life of the process: delete what has passed its time every RETENTION_INTERVAL_SECONDS."""
    while True:
        try:
            await run_all()
        except Exception as e:  # never let the loop die
            logger.error(f"Retention failed: {e}")
        await asyncio.sleep(settings.RETENTION_INTERVAL_SECONDS)
