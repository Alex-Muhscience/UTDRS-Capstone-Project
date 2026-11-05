"""
Watching the platform's own health, and saying so when something stops working.

Every HEALTH_CHECK_INTERVAL_SECONDS, one process (whichever takes the round's lease) checks:

For whoever runs the deployment (OPERATOR_EMAILS):
- the core engine answers;
- events do not wait for analysis longer than ANALYSIS_BACKLOG_ALERT_MINUTES;
- email is being sent (none failing for good in the last hour);
- each background loop is still running (heartbeat.py).

For each organisation's administrators:
- each connector polls without errors;
- a connector brings data in at least every CONNECTOR_SILENT_HOURS.

A problem is reported once it has lasted HEALTH_ALERT_AFTER_MINUTES (so a blip says
nothing), once, and again when it is over. The state is kept in `health_checks`, one
document per check, so the whole deployment reports each problem once.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from pymongo import ReturnDocument

from config import settings
from core.database.connection import get_database
from core.services import core_engine_client, heartbeat, notifications
from core.tenancy import tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "health_checks"
ROUND_LEASE = "round"

# A check's outcome: None when healthy, otherwise what is wrong, for people.
Problem = Optional[str]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------- Checks

async def _engine() -> Problem:
    client = core_engine_client.get_core_engine_client()
    if client is None or await client.is_healthy():
        return None
    return f"The core engine at {settings.CORE_ENGINE_URL} does not answer its health check. Events are stored and wait to be analysed."


async def _analysis_backlog(now: datetime) -> Problem:
    oldest = await get_database()["events"].find_one(
        {"metadata.analysis.status": {"$in": ["queued", "analysing"]}}, {"metadata.analysis.queued_at": 1},
        sort=[("metadata.analysis.queued_at", 1)],
    )
    queued_at = (((oldest or {}).get("metadata") or {}).get("analysis") or {}).get("queued_at")
    if not queued_at:
        return None
    waited = now - _aware(queued_at)
    if waited < timedelta(minutes=settings.ANALYSIS_BACKLOG_ALERT_MINUTES):
        return None
    waiting = await get_database()["events"].count_documents({"metadata.analysis.status": {"$in": ["queued", "analysing"]}})
    return f"{waiting} events are waiting to be analysed; the oldest for {int(waited.total_seconds() // 60)} minutes."


async def _email(now: datetime) -> Problem:
    if not notifications.configured():
        return None
    failed = await get_database()["notifications"].find_one(
        {"status": "failed", "created_at": {"$gte": now - timedelta(hours=1)}}, sort=[("created_at", -1)]
    )
    if not failed:
        return None
    return f"Emails are failing to send: {failed.get('error') or 'unknown error'}."


async def _loops() -> List[Tuple[str, Problem]]:
    results = []
    for loop in await heartbeat.all_loops():
        problem = None
        if loop["stale"]:
            problem = f"The background loop {loop['_id']} has not run for {int(loop['age_seconds'] // 60)} minutes (last on {loop.get('process')})."
        results.append((f"loop:{loop['_id']}", problem))
    return results


async def _connectors(now: datetime) -> List[Tuple[str, str, str, Problem]]:
    """(check id, organisation, connector, problem) for each connection."""
    results = []
    silent_after = timedelta(hours=settings.CONNECTOR_SILENT_HOURS)
    for connection in await get_database()["connections"].find({}).to_list(10000):
        kind = connection.get("connector") or "connector"
        tenant = connection["tenant_id"]
        errors = connection.get("errors") or {}
        failing = None
        if connection.get("status") == "error" and errors:
            failing = "Polling fails: " + "; ".join(f"{source}: {error}" for source, error in sorted(errors.items()))
        results.append((f"connector:{tenant}:{kind}:errors", tenant, kind, failing))

        silent = None
        since = connection.get("last_data_at") or connection.get("connected_at")
        if connection.get("status") == "connected" and since and now - _aware(since) > silent_after:
            silent = f"Nothing has arrived for {int((now - _aware(since)).total_seconds() // 3600)} hours."
        results.append((f"connector:{tenant}:{kind}:silent", tenant, kind, silent))
    return results


# ---------------------------------------------------------------------------- State and alerts

async def _transition(check: str, problem: Problem, now: datetime) -> Tuple[Optional[str], Problem]:
    """
    Record the check's outcome. Returns "failing" when the problem should now be reported
    (it has lasted long enough, and was not reported yet), "recovered" when a reported
    problem is over, or None; and the problem (for a recovery, the one that is over).
    """
    checks = get_database()[COLLECTION]
    state = await checks.find_one({"_id": check}) or {}
    if problem is None:
        if state.get("failing"):
            await checks.update_one({"_id": check}, {"$set": {"failing": False, "problem": None, "since": None, "recovered_at": now}})
            return ("recovered" if state.get("reported_at") else None), state.get("problem")
        return None, None
    was_failing = bool(state.get("failing"))
    since = _aware(state["since"]) if was_failing and state.get("since") else now
    reported_at = state.get("reported_at") if was_failing else None
    due = reported_at is None and now - since >= timedelta(minutes=settings.HEALTH_ALERT_AFTER_MINUTES)
    await checks.update_one({"_id": check}, {"$set": {
        "failing": True, "problem": problem, "since": since, "checked_at": now, "reported_at": now if due else reported_at,
    }}, upsert=True)
    return ("failing" if due else None), problem


async def _tell_operators(check: str, problem: Problem, outcome: str) -> None:
    subject = f"[UTDRS] {'Problem' if outcome == 'failing' else 'Resolved'}: {check}"
    text = (f"{problem}\n\nIt has lasted {settings.HEALTH_ALERT_AFTER_MINUTES} minutes or more." if outcome == "failing"
            else f"{check} is working again.")
    logger.warning(f"Platform health: {subject}")
    for address in settings.OPERATOR_EMAILS:
        try:
            await notifications.send_email(address, subject, text + "\n\n— UTDRS platform health\n")
        except Exception as e:  # email may be what is broken; the log has it
            logger.error(f"Could not email {address} about {check}: {e}")


async def _tell_organisation(tenant: str, kind: str, problem: Problem, outcome: str) -> None:
    """Email the organisation's administrators (connectors already send webhooks as they fail)."""
    name = {"m365": "Microsoft 365"}.get(kind, kind)
    with tenant_context(tenant):
        admins = await notifications._people(role="admin")
        if outcome == "failing":
            subject = f"[UTDRS] The {name} connection needs attention"
            text = f"{problem}\n\nUntil it is fixed, UTDRS does not see what happens in {name}. Check the connection in UTDRS."
        else:
            subject = f"[UTDRS] The {name} connection is working again"
            text = f"UTDRS is receiving data from {name} again."
        await notifications._enqueue("connector_health", admins, subject, text, notifications._link("/connectors"), {"type": "connector", "id": kind})


async def check_once() -> Dict[str, int]:
    """One round of every check. Returns how many problems were reported and how many ended."""
    now = utcnow()
    reported = recovered = 0

    platform: List[Tuple[str, Problem]] = [("core_engine", await _engine()), ("analysis_backlog", await _analysis_backlog(now)),
                                           ("email", await _email(now))]
    platform += await _loops()
    for check, problem in platform:
        outcome, about = await _transition(check, problem, now)
        if outcome:
            await _tell_operators(check, about, outcome)
            reported += outcome == "failing"
            recovered += outcome == "recovered"

    for check, tenant, kind, problem in await _connectors(now):
        outcome, about = await _transition(check, problem, now)
        if outcome:
            await _tell_organisation(tenant, kind, about, outcome)
            reported += outcome == "failing"
            recovered += outcome == "recovered"
    return {"reported": reported, "recovered": recovered}


async def _take_round(now: datetime) -> bool:
    """Whether this process runs this round: one process per round across the deployment."""
    interval = timedelta(seconds=settings.HEALTH_CHECK_INTERVAL_SECONDS)
    taken = await get_database()[COLLECTION].find_one_and_update(
        {"_id": ROUND_LEASE, "$or": [{"until": {"$lte": now}}, {"until": {"$exists": False}}]},
        {"$set": {"until": now + interval - timedelta(seconds=1)}}, return_document=ReturnDocument.AFTER,
    )
    if taken:
        return True
    try:
        await get_database()[COLLECTION].insert_one({"_id": ROUND_LEASE, "until": now + interval - timedelta(seconds=1)})
        return True
    except Exception:  # another process created it first
        return False


async def check_periodically() -> None:
    while True:
        error = None
        try:
            if await _take_round(utcnow()):
                await check_once()
        except Exception as e:  # never let the loop die
            logger.error(f"Platform health check failed: {e}")
            error = e
        await heartbeat.beat("platform_health", settings.HEALTH_CHECK_INTERVAL_SECONDS, error)
        await asyncio.sleep(settings.HEALTH_CHECK_INTERVAL_SECONDS)


async def summary() -> Dict[str, Any]:
    """What is failing now, for the readiness check."""
    failing = await get_database()[COLLECTION].find({"failing": True}, {"problem": 1, "since": 1}).to_list(100)
    return {item["_id"]: {"problem": item.get("problem"), "since": item.get("since")} for item in failing if not item["_id"].startswith("connector:")}
