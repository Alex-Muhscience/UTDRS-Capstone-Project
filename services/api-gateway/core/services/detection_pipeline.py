"""
Event -> core engine -> alert.

Runs after an event is stored (as a background task, so ingestion never waits on, or
fails because of, the engine). The outcome is recorded on the event as
metadata.analysis, and a threat becomes an alert linked to the event.
"""
from typing import Any, Dict, Optional

from core.database.repositories.event_repository import EventRepository
from core.models.alert import AlertCreate
from core.models.event import EventCreate
from core.services import core_engine_client
from core.services.alert_service import AlertService
from core.tenancy import current_tenant
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


def to_engine_event(event_id: str, event: EventCreate) -> Dict[str, Any]:
    """The gateway's event in the shape the core engine's /detections/process expects."""
    data: Dict[str, Any] = dict(event.raw_data or {})
    for field, names in DETECTOR_FIELDS.items():
        value = getattr(event, field)
        if value is not None:
            for name in names:
                data.setdefault(name, value)
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


async def analyse_event(event_id: str, event: EventCreate) -> Optional[str]:
    """Run detection for a stored event. Returns the new alert's id, if any."""
    client = core_engine_client.get_core_engine_client()
    if client is None:
        return None

    events = EventRepository()
    analysis: Dict[str, Any] = {"analysed_at": utcnow()}
    alert_id: Optional[str] = None
    try:
        engine_alert = await client.analyse_event(to_engine_event(event_id, event))
        if engine_alert:
            alert_id = await AlertService().create_alert(
                to_gateway_alert(engine_alert, event_id, event),
                metadata={
                    "core_engine_alert_id": engine_alert.get("id"),
                    "detection_type": engine_alert.get("detection_type"),
                    "details": engine_alert.get("details") or {},
                },
            )
            analysis.update(status="threat", alert_id=alert_id)
            logger.info(f"Event {event_id} raised alert {alert_id}")
        else:
            analysis["status"] = "clean"
    except core_engine_client.CoreEngineError as exc:
        logger.error(f"Core engine analysis failed for event {event_id}: {exc}")
        analysis.update(status="error", error=str(exc))

    await events.update_one(event_id, {"metadata.analysis": analysis})
    return alert_id
