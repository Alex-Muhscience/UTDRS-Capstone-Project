"""
Event -> core engine -> alert, through a queue that loses nothing.

An event to analyse is marked queued on the event itself (metadata.analysis), so the
queue lives in the database: it survives restarts, and any gateway process can work it.
The request that stored the event tries straight away, in the background; if the engine
cannot be reached, or answers with an error, the event is tried again later, waiting
longer each time, for up to ANALYSIS_GIVE_UP_HOURS (analyse_periodically). Each attempt
claims the event for a while (a lease), so two processes never analyse it at once, and
an attempt lost with its process is picked up again when the lease ends. An event the
engine rejects as invalid is not retried. Events can be queued again (replay), such as
those that failed while the engine was down for longer.

The outcome is recorded on the event, and a threat becomes an alert linked to the event,
once, however many attempts it took.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId
from pymongo import ReturnDocument

from config import settings
from core.database.connection import get_database
from core.database.repositories.event_repository import EventRepository
from core.models.alert import AlertCreate
from core.models.event import EventCreate
from core.services import core_engine_client
from core.services.alert_service import AlertService
from core.tenancy import current_tenant, tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Event fields the engine's detectors read from event["data"], with the names they expect.
DETECTOR_FIELDS = {
    "source_ip": ["source_ip", "src_ip"],
    "destination_ip": ["destination_ip", "dst_ip"],
    "protocol": ["protocol"],
    "action": ["action"],
    "user_id": ["user_id"],
    "asset_id": ["asset_id"],
    "description": ["description"],
}

QUEUED, ANALYSING = "queued", "analysing"
LEASE = timedelta(minutes=2)
FIRST_RETRY_SECONDS, LONGEST_WAIT_SECONDS = 15, 600
STATUS = "metadata.analysis.status"
NEXT = "metadata.analysis.next_attempt_at"
LEASE_UNTIL = "metadata.analysis.lease_until"


def to_engine_event(event_id: str, event: EventCreate, transient: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    The gateway's event in the shape the core engine's /detections/process expects.
    `transient` is data the engine needs to judge the event but the gateway does not keep,
    such as an email's body.
    """
    data: Dict[str, Any] = {**(event.raw_data or {}), **(transient or {})}
    for field, names in DETECTOR_FIELDS.items():
        value = getattr(event, field)
        if value is not None:
            for name in names:
                data.setdefault(name, value)
    # The engine keeps each event once, by this id, however often it is sent.
    data["gateway_event_id"] = event_id
    return {
        # The engine keeps each organisation's history and rules apart.
        "tenant_id": current_tenant(),
        "source": event.source,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat(),
        "data": data,
    }


def to_gateway_alert(engine_alert: Dict[str, Any], event_id: str, event: EventCreate) -> AlertCreate:
    details = engine_alert.get("details") or {}
    severity = str(engine_alert.get("severity", "medium")).lower()
    return AlertCreate(
        title=engine_alert.get("title") or "Threat detected",
        description=engine_alert.get("description") or "",
        severity=severity if severity in SEVERITIES else "medium",
        source="core-engine",
        type=engine_alert.get("detection_type") or "detection",
        tags=list(details.get("tags") or []),
        asset_ids=[event.asset_id] if event.asset_id else [],
        event_ids=[event_id],
    )


# ---------------------------------------------------------------------------- The queue

def _events():
    return get_database()["events"]  # the queue spans organisations; each attempt runs in its event's


async def ensure_indexes() -> None:
    await _events().create_index([(STATUS, 1), (NEXT, 1)])
    await _events().create_index([("tenant_id", 1), (STATUS, 1), ("metadata.analysis.analysed_at", -1)])


def retry_delay(attempts: int) -> timedelta:
    """15 seconds after the first failure, doubling each time, at most ten minutes."""
    return timedelta(seconds=min(FIRST_RETRY_SECONDS * 2 ** min(max(attempts - 1, 0), 10), LONGEST_WAIT_SECONDS))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _queued(now: datetime) -> Dict[str, Any]:
    return {"status": QUEUED, "queued_at": now, "attempts": 0, "next_attempt_at": now}


async def queue(event_id: str) -> bool:
    """Mark a stored event to be analysed. False when there is no core engine to analyse it."""
    if core_engine_client.get_core_engine_client() is None:
        return False
    await EventRepository().update_one(event_id, {"metadata.analysis": _queued(utcnow())})
    return True


async def _claim(query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """An event that is due (or whose last attempt was lost), now ours for LEASE."""
    now = utcnow()
    due = {"$or": [{STATUS: QUEUED, NEXT: {"$lte": now}}, {STATUS: ANALYSING, LEASE_UNTIL: {"$lte": now}}]}
    return await _events().find_one_and_update(
        {**query, **due},
        {"$set": {STATUS: ANALYSING, LEASE_UNTIL: now + LEASE}, "$inc": {"metadata.analysis.attempts": 1}},
        sort=[(NEXT, 1)], return_document=ReturnDocument.AFTER,
    )


def _stored_event(doc: Dict[str, Any]) -> EventCreate:
    return EventCreate.model_validate({name: doc[name] for name in EventCreate.model_fields if name in doc})


async def _alert_for(event_id: str, engine_alert: Dict[str, Any], event: EventCreate) -> str:
    """The event's alert: one an earlier attempt made before it was cut short, or a new one."""
    existing = await get_database()["alerts"].find_one(
        {"tenant_id": current_tenant(), "event_ids": event_id, "source": "core-engine"}, {"_id": 1}
    )
    if existing:
        return str(existing["_id"])
    return await AlertService().create_alert(
        to_gateway_alert(engine_alert, event_id, event),
        metadata={
            "core_engine_alert_id": engine_alert.get("id"),
            "detection_type": engine_alert.get("detection_type"),
            "details": engine_alert.get("details") or {},
        },
    )


async def _attempt(
    event_id: str, event: EventCreate, previous: Dict[str, Any], transient: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[str], Optional[core_engine_client.CoreEngineError]]:
    """
    One attempt at a claimed event; records the outcome on it. Returns the alert's id, if
    any, and the engine's error, if it failed. Data passed in `transient` is not kept, so an
    attempt that needs it is not retried.
    """
    client = core_engine_client.get_core_engine_client()
    now = utcnow()
    attempts = previous.get("attempts") or 1
    queued_at = previous.get("queued_at") or now
    try:
        if client is None:
            raise core_engine_client.CoreEngineError("No core engine is configured", 400)
        engine_alert = await client.analyse_event(to_engine_event(event_id, event, transient))
    except core_engine_client.CoreEngineError as exc:
        too_long = now - _aware(queued_at) >= timedelta(hours=settings.ANALYSIS_GIVE_UP_HOURS)
        give_up = not exc.retryable or transient is not None or too_long
        logger.warning(f"Analysing event {event_id} failed (attempt {attempts}{', giving up' if give_up else ''}): {exc}")
        outcome = {"status": "error", "analysed_at": now} if give_up else {"status": QUEUED, "next_attempt_at": now + retry_delay(attempts)}
        await EventRepository().update_one(event_id, {"metadata.analysis": {
            **outcome, "queued_at": queued_at, "attempts": attempts, "error": str(exc)[:500],
        }})
        return None, exc

    alert_id = await _alert_for(event_id, engine_alert, event) if engine_alert else None
    analysis: Dict[str, Any] = {"status": "threat" if alert_id else "clean", "analysed_at": utcnow(), "queued_at": queued_at, "attempts": attempts}
    if alert_id:
        analysis["alert_id"] = alert_id
        logger.info(f"Event {event_id} raised alert {alert_id}")
    await EventRepository().update_one(event_id, {"metadata.analysis": analysis})
    return alert_id, None


async def analyse_queued(event_id: str) -> Optional[str]:
    """Try a queued event now (unless another process has it). Returns the new alert's id, if any."""
    if not ObjectId.is_valid(event_id):
        return None
    claimed = await _claim({"_id": ObjectId(event_id), "tenant_id": current_tenant()})
    if not claimed:
        return None
    alert_id, _ = await _attempt(event_id, _stored_event(claimed), claimed["metadata"]["analysis"])
    return alert_id


async def analyse_event(event_id: str, event: EventCreate, transient: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Analyse a stored event now. Returns the new alert's id, if any. A failure leaves the
    event queued, to be tried again, unless it needed `transient` data (an email's body),
    which is not kept.
    """
    if transient is None:
        return await analyse_queued(event_id) if await queue(event_id) else None
    if core_engine_client.get_core_engine_client() is None:
        return None
    alert_id, _ = await _attempt(event_id, event, {"attempts": 1, "queued_at": utcnow()}, transient)
    return alert_id


async def analyse_due(limit: int = 500) -> int:
    """
    Work through the queued events that are due, for every organisation, a few at once
    (ANALYSIS_CONCURRENCY). Stops when the engine cannot be reached, so an outage costs
    one attempt per round rather than one per event. Returns how many were analysed.
    """
    if core_engine_client.get_core_engine_client() is None:
        return 0
    done = 0
    engine_down = asyncio.Event()

    async def worker() -> None:
        nonlocal done
        while done < limit and not engine_down.is_set():
            claimed = await _claim({})
            if not claimed:
                return
            with tenant_context(claimed["tenant_id"]):
                _, error = await _attempt(str(claimed["_id"]), _stored_event(claimed), claimed["metadata"]["analysis"])
            if error is None:
                done += 1
            elif error.retryable:
                engine_down.set()

    await asyncio.gather(*(worker() for _ in range(max(1, settings.ANALYSIS_CONCURRENCY))))
    return done


async def analyse_periodically() -> None:
    from core.services import heartbeat

    while True:
        error = None
        try:
            await analyse_due()
        except Exception as e:  # never let the loop die
            logger.error(f"Analysing queued events failed: {e}")
            error = e
        await heartbeat.beat("analysis", settings.ANALYSIS_INTERVAL_SECONDS, error)
        await asyncio.sleep(settings.ANALYSIS_INTERVAL_SECONDS)


async def queue_status() -> Dict[str, Any]:
    """This organisation's queue: how many events wait and since when, and how many failed for good in a day."""
    tenant = current_tenant()
    waiting = {"tenant_id": tenant, STATUS: {"$in": [QUEUED, ANALYSING]}}
    oldest = await _events().find_one(waiting, {"metadata.analysis.queued_at": 1}, sort=[("metadata.analysis.queued_at", 1)])
    return {
        "waiting": await _events().count_documents(waiting),
        "oldest_waiting_since": (((oldest or {}).get("metadata") or {}).get("analysis") or {}).get("queued_at"),
        "failed_last_day": await _events().count_documents(
            {"tenant_id": tenant, STATUS: "error", "metadata.analysis.analysed_at": {"$gte": utcnow() - timedelta(days=1)}}
        ),
    }


async def requeue(event_ids: Optional[List[str]] = None, failed_since: Optional[datetime] = None) -> int:
    """
    Queue events of this organisation to be analysed again (replay): the ones named, or
    else every one whose analysis failed (since `failed_since`, when given). Returns how many.
    """
    if core_engine_client.get_core_engine_client() is None:
        return 0
    query: Dict[str, Any] = {"tenant_id": current_tenant()}
    if event_ids is not None:
        query["_id"] = {"$in": [ObjectId(i) for i in event_ids if ObjectId.is_valid(i)]}
        query[STATUS] = {"$nin": [QUEUED, ANALYSING]}
    else:
        query[STATUS] = "error"
        if failed_since:
            query["metadata.analysis.analysed_at"] = {"$gte": failed_since}
    result = await _events().update_many(query, {"$set": {"metadata.analysis": _queued(utcnow())}})
    return result.modified_count
