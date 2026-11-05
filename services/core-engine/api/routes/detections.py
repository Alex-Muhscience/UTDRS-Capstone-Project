from fastapi import APIRouter, Depends, HTTPException, status, Body
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from core.models.schema.alert import AlertCreate, Alert

router = APIRouter()

# We'll initialize the detection engine lazily instead of at module load time
# This helps avoid circular imports and database connection issues
from core.detection.engine import DetectionEngine
_detection_engine = None

def get_detection_engine():
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine

class EventData(BaseModel):
    # The organisation the event belongs to; its history and rules are kept apart.
    tenant_id: Optional[str] = None
    source: str
    event_type: str
    timestamp: str
    data: Dict[str, Any]

@router.post("/process", response_model=Optional[Alert])
async def process_event_data(event: EventData):
    '''Process an event and generate an alert if a threat is detected.'''
    from core.services.event_processor import process_event
    from core.tenancy import DEFAULT_TENANT, tenant_context

    payload = event.model_dump()
    with tenant_context(payload.pop("tenant_id") or DEFAULT_TENANT):
        return await process_event(payload)

MAX_BATCH = 100


class EventBatch(BaseModel):
    events: List[EventData]


class BatchItem(BaseModel):
    # The alert raised, or null for no threat; `error` when the event could not be analysed.
    alert: Optional[Alert] = None
    error: Optional[str] = None


@router.post("/process/batch", response_model=List[BatchItem])
async def process_event_batch(batch: EventBatch):
    """
    Analyse up to 100 events in one request, in order (so correlations see them as they
    happened): one round trip instead of one each. Each event's result is in the same place
    in the answer; one that fails says why and the rest still go through.
    """
    from fastapi import HTTPException

    from core.services.event_processor import process_event
    from core.tenancy import DEFAULT_TENANT, tenant_context

    if len(batch.events) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"At most {MAX_BATCH} events in a batch")
    results: List[BatchItem] = []
    for event in batch.events:
        payload = event.model_dump()
        try:
            with tenant_context(payload.pop("tenant_id") or DEFAULT_TENANT):
                results.append(BatchItem(alert=await process_event(payload)))
        except Exception as e:  # this event's problem, not the batch's
            results.append(BatchItem(error=f"{e.__class__.__name__}: {e}"[:300]))
    return results


@router.get("/alerts", response_model=List[Alert])
async def get_alerts(
    severity: Optional[str] = None, 
    source: Optional[str] = None, 
    limit: int = 100, 
    skip: int = 0
):
    '''Get alerts based on filters.'''
    detection_engine = get_detection_engine()
    filters = {}
    if severity:
        filters["severity"] = severity
    if source:
        filters["source"] = source
        
    alerts = await detection_engine.get_alerts(filters, limit, skip)
    return alerts

@router.get("/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str):
    '''Get a specific alert by ID.'''
    detection_engine = get_detection_engine()
    alert = await detection_engine.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    return alert