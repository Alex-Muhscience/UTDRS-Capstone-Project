"""
The monthly report: a month of security in plain words, for the people who run the business.

For one calendar month (UTC) of the current organisation: what was found and dealt with,
what UTDRS did about it, what is still open, how this compares with the month before,
and what to do next. It is built from the organisation's alerts, cases, actions and
assets, stored (so it does not change as data ages out) and shown on the web and as a
PDF. The month before's report is made on the first of each month, and administrators
are emailed when it is ready; anyone can (re)make a report for any month.
"""
import asyncio
from calendar import month_name
from collections import Counter
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from config import settings
from core.database.connection import get_database
from core.services import case_service, connectors, tenants
from core.tenancy import current_tenant, scoped, tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "reports"
CLOSED = ("resolved", "false_positive", "closed")
MAX_ITEMS = 20000  # per collection and month; beyond this, a report counts what it can


def _reports():
    return scoped(get_database(), COLLECTION)


async def ensure_indexes() -> None:
    await get_database()[COLLECTION].create_index([("tenant_id", 1), ("period", 1)], unique=True)


def month_bounds(period: str) -> Tuple[datetime, datetime]:
    year, month = (int(part) for part in period.split("-"))
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=timezone.utc)
    return start, end


def previous_period(period: str) -> str:
    start, _ = month_bounds(period)
    before = start - timedelta(days=1)
    return f"{before.year:04d}-{before.month:02d}"


def last_full_month(now: Optional[datetime] = None) -> str:
    return previous_period(f"{(now or utcnow()):%Y-%m}")


def month_title(period: str) -> str:
    year, month = period.split("-")
    return f"{month_name[int(month)]} {year}"


def _closed_at(case: Dict[str, Any]) -> Optional[datetime]:
    """When the case was first resolved, closed or marked a false positive."""
    for entry in case.get("timeline", []):
        if entry.get("kind") == "status_changed" and (entry.get("data") or {}).get("after") in CLOSED:
            return entry["at"]
    return None


def _change(value: Optional[float], previous: Optional[float]) -> Dict[str, Optional[float]]:
    return {"value": value, "previous": previous}


async def _month(start: datetime, end: datetime) -> Dict[str, Any]:
    """The raw figures for one month."""
    database = get_database()
    alerts = await scoped(database, "alerts").find(
        {"created_at": {"$gte": start, "$lt": end}}, {"severity": 1, "title": 1, "tags": 1, "metadata.details.mitre_techniques": 1, "created_at": 1}
    ).to_list(MAX_ITEMS)
    opened = await scoped(database, "cases").find({"created_at": {"$gte": start, "$lt": end}}, {"timeline": 0}).to_list(MAX_ITEMS)
    # Cases closed this month may have opened earlier.
    candidates = await scoped(database, "cases").find(
        {"status": {"$in": list(CLOSED)}, "updated_at": {"$gte": start}, "created_at": {"$lt": end}},
        {"priority": 1, "created_at": 1, "due_at": 1, "timeline": 1},
    ).to_list(MAX_ITEMS)
    closed = [(c, at) for c in candidates if (at := _closed_at(c)) and start <= at < end]
    actions = await scoped(database, "actions").find({"created_at": {"$gte": start, "$lt": end}}).to_list(MAX_ITEMS)
    hours = [(at - c["created_at"]).total_seconds() / 3600 for c, at in closed]
    in_time = [at <= c["due_at"] for c, at in closed]
    ran = [a for a in actions if a.get("status") in ("succeeded", "undone")]
    return {
        "alerts": alerts,
        "opened": opened,
        "closed": closed,
        "actions": actions,
        "figures": {
            "alerts": len(alerts),
            "cases_opened": len(opened),
            "cases_closed": len(closed),
            "critical_cases": sum(c["priority"] == "critical" for c in opened),
            "actions_taken": len(ran),
            "median_hours_to_resolve": round(median(hours), 1) if hours else None,
            "within_deadline_percent": round(100 * sum(in_time) / len(in_time)) if in_time else None,
        },
    }


def _weekly(alerts: List[Dict[str, Any]], start: datetime, end: datetime) -> List[Dict[str, Any]]:
    weeks, day = [], start
    while day < end:
        until = min(day + timedelta(days=7), end)
        weeks.append({"start": day, "end": until, "count": sum(day <= a["created_at"] < until for a in alerts)})
        day = until
    return weeks


def _threats(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What the month's alerts were about: ATT&CK techniques in words where known, else their titles."""
    counts: Counter = Counter()
    for alert in alerts:
        techniques = case_service._techniques(alert)
        words = [case_service.TECHNIQUES.get(t) or case_service.TECHNIQUES.get(t.split(".")[0]) for t in techniques]
        words = [w for w in dict.fromkeys(words) if w]
        for name in words or [alert.get("title") or "Unnamed alert"]:
            counts[name[:1].upper() + name[1:]] += 1
    return [{"name": name, "count": count} for name, count in counts.most_common(5)]


async def _targets(opened: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The users and devices most often involved in the month's cases."""
    await case_service._name_assets(opened)
    counts: Counter = Counter()
    for case in opened:
        for entity in case.get("entities", []):
            if entity["type"] in ("user", "host", "asset"):
                counts[("user" if entity["type"] == "user" else "device", entity.get("name") or entity["value"])] += 1
    return [{"type": kind, "name": name, "cases": count} for (kind, name), count in counts.most_common(5)]


def _actions(actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    from core.services.response_actions import CATALOGUE

    ran = [a for a in actions if a.get("status") in ("succeeded", "undone")]
    by_action = Counter(CATALOGUE[a["action"]].label if a["action"] in CATALOGUE else a["action"] for a in ran)
    return {
        "taken": len(ran),
        "automatic": sum(bool(a.get("auto")) for a in ran),
        "approved": sum(not a.get("auto") and a.get("mode") != "automatic" for a in ran),
        "undone": sum(a.get("status") == "undone" for a in actions),
        "failed": sum(a.get("status") == "failed" for a in actions),
        "rejected": sum(a.get("status") == "rejected" for a in actions),
        "by_action": [{"label": label, "count": count} for label, count in by_action.most_common()],
    }


async def _outstanding(at: datetime) -> Dict[str, Any]:
    """Cases still open when the report is made, and actions still waiting for a decision."""
    database = get_database()
    open_cases = await scoped(database, "cases").find({"status": {"$in": case_service.OPEN}}, {"timeline": 0}).to_list(MAX_ITEMS)
    order = case_service.PRIORITIES
    open_cases.sort(key=lambda c: (-order.index(c["priority"]), c["due_at"]))
    overdue = [c for c in open_cases if c["due_at"] < at]
    return {
        "open_cases": len(open_cases),
        "overdue": len(overdue),
        "by_priority": dict(Counter(c["priority"] for c in open_cases)),
        "top": [
            {"id": str(c["_id"]), "title": c["title"], "priority": c["priority"], "due_at": c["due_at"], "overdue": c["due_at"] < at}
            for c in open_cases[:5]
        ],
        "awaiting_approval": await scoped(database, "actions").count_documents({"status": "pending"}),
    }


def _headline(title: str, this: Dict[str, Any], outstanding: Dict[str, Any]) -> List[str]:
    f = this["figures"]
    if not f["alerts"] and not f["cases_opened"]:
        lines = [f"In {title}, UTDRS found nothing that needed attention."]
    else:
        lines = [
            f"In {title}, UTDRS raised {f['alerts']} alert{'s' if f['alerts'] != 1 else ''}, grouped into "
            f"{f['cases_opened']} case{'s' if f['cases_opened'] != 1 else ''}"
            + (f", {f['critical_cases']} of them critical." if f["critical_cases"] else ".")
        ]
        done = f"{f['cases_closed']} case{'s were' if f['cases_closed'] != 1 else ' was'} dealt with"
        if f["actions_taken"]:
            done += f" and {f['actions_taken']} response action{'s were' if f['actions_taken'] != 1 else ' was'} taken"
        lines.append(done + ".")
        if f["within_deadline_percent"] is not None:
            lines.append(f"{f['within_deadline_percent']}% of cases were dealt with within their deadline.")
    if outstanding["open_cases"]:
        lines.append(
            f"{outstanding['open_cases']} case{'s are' if outstanding['open_cases'] != 1 else ' is'} still open"
            + (f", {outstanding['overdue']} overdue." if outstanding["overdue"] else ".")
        )
    else:
        lines.append("No cases are open.")
    return lines


async def _recommendations(this: Dict[str, Any], outstanding: Dict[str, Any]) -> List[str]:
    advice = []
    if outstanding["overdue"]:
        first = next(c for c in outstanding["top"] if c["overdue"]) if any(c["overdue"] for c in outstanding["top"]) else None
        advice.append(f"Deal with the {outstanding['overdue']} overdue case{'s' if outstanding['overdue'] != 1 else ''}"
                      + (f", starting with \"{first['title']}\"." if first else "."))
    if outstanding["awaiting_approval"]:
        n = outstanding["awaiting_approval"]
        advice.append(f"Decide on the {n} response action{'s' if n != 1 else ''} waiting for approval.")
    percent = this["figures"]["within_deadline_percent"]
    if percent is not None and percent < 80:
        advice.append("Fewer than 8 in 10 cases were dealt with in time: give every new case an owner as it arrives.")
    if not await connectors.connected("m365"):
        advice.append("Connect Microsoft 365, so UTDRS can watch sign-ins and email and act on account and phishing threats for you.")
    if this["actions"] and sum(a.get("status") == "failed" for a in this["actions"]):
        advice.append("Some response actions failed: check the Response page for why.")
    return advice or ["Nothing needs your attention: keep UTDRS connected and review this report next month."]


async def build(period: str, at: Optional[datetime] = None) -> Dict[str, Any]:
    """The report for `period` ("YYYY-MM") of the current organisation, as of `at`."""
    at = at or utcnow()
    start, end = month_bounds(period)
    previous_start, _ = month_bounds(previous_period(period))
    this, before = await _month(start, end), await _month(previous_start, start)
    outstanding = await _outstanding(at)
    tenant = await tenants.get(current_tenant()) or {}
    title = month_title(period)
    return {
        "period": period,
        "title": title,
        "organisation": tenant.get("name", ""),
        "start": start,
        "end": end,
        "headline": _headline(title, this, outstanding),
        "figures": {name: _change(value, before["figures"][name]) for name, value in this["figures"].items()},
        "alerts_by_severity": dict(Counter(a.get("severity", "info") for a in this["alerts"])),
        "weekly_alerts": _weekly(this["alerts"], start, end),
        "top_threats": _threats(this["alerts"]),
        "most_targeted": await _targets(this["opened"]),
        "actions": _actions(this["actions"]),
        "outstanding": outstanding,
        "recommendations": await _recommendations(this, outstanding),
    }


async def generate(period: str, actor: Dict[str, Any]) -> Dict[str, Any]:
    """Make (or remake) the report for `period`, and keep it."""
    data = await build(period)
    now = utcnow()
    return await _reports().find_one_and_replace(
        {"period": period}, {"period": period, "generated_at": now, "generated_by": actor, "data": data},
        upsert=True, return_document=ReturnDocument.AFTER,
    )


async def list_reports() -> List[Dict[str, Any]]:
    return await _reports().find({}, {"data.headline": 1, "data.title": 1, "period": 1, "generated_at": 1, "generated_by": 1}).sort("period", -1).to_list(120)


async def get(report_id: str) -> Optional[Dict[str, Any]]:
    return await _reports().find_one({"_id": ObjectId(report_id)}) if ObjectId.is_valid(report_id) else None


async def generate_due(now: Optional[datetime] = None) -> int:
    """Make last month's report for every organisation that does not have it yet, and tell its administrators."""
    from core.services import notifications

    now = now or utcnow()
    period = last_full_month(now)
    _, end = month_bounds(period)
    made = 0
    for tenant_id in await tenants.all_ids():
        tenant = await tenants.get(tenant_id)
        if not tenant or tenant["created_at"] >= end:
            continue  # it did not exist that month
        with tenant_context(tenant_id):
            if await _reports().find_one({"period": period}, {"_id": 1}):
                continue
            data = await build(period, now)
            try:
                result = await _reports().insert_one({"period": period, "generated_at": now, "generated_by": {"type": "schedule", "name": "Monthly"}, "data": data})
            except DuplicateKeyError:
                continue  # another process made it first, and tells people
            await notifications.report_ready({"_id": result.inserted_id, "period": period, "data": data})
            from core.services import webhooks

            await webhooks.emit("report.ready", {"id": str(result.inserted_id), "period": period, "title": data["title"],
                                                 "headline": data["headline"], "url": settings.DASHBOARD_URL.rstrip("/") + f"/reports/{result.inserted_id}"})
            made += 1
    return made


async def generate_periodically() -> None:
    """Run for the life of the process: check every REPORT_CHECK_INTERVAL_SECONDS for reports due."""
    while True:
        try:
            made = await generate_due()
            if made:
                logger.info(f"Made {made} monthly reports")
        except Exception as e:  # never let the loop die
            logger.error(f"Monthly reports failed: {e}")
        await asyncio.sleep(settings.REPORT_CHECK_INTERVAL_SECONDS)
