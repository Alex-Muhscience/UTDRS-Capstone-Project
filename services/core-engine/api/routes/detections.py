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
    source: str
    event_type: str
    timestamp: str
    data: Dict[str, Any]

@router.post("/process", response_model=Optional[Alert])
async def process_event_data(event: EventData):
    '''Process an event and generate an alert if a threat is detected.'''
    from core.services.event_processor import process_event
    alert = await process_event(event.dict())
    return alert

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