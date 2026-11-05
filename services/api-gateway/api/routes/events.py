import json
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from core.models.event import Event, EventCreate, EventUpdate
from core.models.user import User
from core.services import audit, detection_pipeline, idempotency
from core.services.event_service import EventService
from utils.security import get_current_active_user, require_admin

router = APIRouter()


@router.get("/", response_model=List[Event])
async def get_events(
    event_type: Optional[str] = None,
    asset_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get events with optional filtering.

    - **event_type**: Filter by event type
    - **asset_id**: Filter by asset ID
    - **user_id**: Filter by user ID
    - **ip_address**: Filter by source or destination IP
    - **limit**: Maximum number of events to return
    - **skip**: Number of events to skip (for pagination)
    """
    event_service = EventService()

    if event_type:
        return await event_service.get_events_by_type(event_type, limit, skip)
    elif asset_id:
        return await event_service.get_events_by_asset(asset_id, limit, skip)
    elif user_id:
        return await event_service.get_events_by_user(user_id, limit, skip)
    elif ip_address:
        return await event_service.get_events_by_ip(ip_address, limit, skip)
    else:
        return await event_service.get_events(limit, skip)


MAX_BATCH = 500


async def _store(event: EventCreate, background_tasks: BackgroundTasks) -> Tuple[str, bool]:
    """Store an event (once, by its external_id) and queue it for analysis. Returns its id and whether it was already there."""
    event_id, duplicate = await EventService().create_event_once(event)
    if not duplicate and await detection_pipeline.queue(event_id):
        background_tasks.add_task(detection_pipeline.analyse_queued, event_id)
    return event_id, duplicate


@router.post("/", response_model=Event, status_code=status.HTTP_201_CREATED,
             responses={200: {"model": Event, "description": "Already received: the event with this source and external_id"}})
async def create_event(
    event: EventCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
):
    """
    Create a new event.

    When a core engine is configured, the event is queued and analysed in the background;
    if the engine cannot be reached it is tried again until it can (for up to a day). The
    result is recorded on the event (metadata.analysis) and a threat raises an alert.

    Sending again is safe: an event with the same `source` and `external_id` is stored
    once (200 with the stored event, `X-Duplicate: true`), and a request repeated with the
    same `Idempotency-Key` header gets the first answer.
    """
    record, replay = await idempotency.begin(request, event.model_dump_json().encode())
    if replay:
        return JSONResponse(status_code=replay["status_code"], content=replay["content"], headers={"Idempotent-Replayed": "true"})
    try:
        event_id, duplicate = await _store(event, background_tasks)
        stored = await EventService().get_event_by_id(event_id)
        if not stored:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create event")
    except BaseException:
        await idempotency.abandon(record)
        raise
    code = status.HTTP_200_OK if duplicate else status.HTTP_201_CREATED
    content = jsonable_encoder(Event(**stored))
    await idempotency.finish(record, code, content)
    return JSONResponse(status_code=code, content=content, headers={"X-Duplicate": "true"} if duplicate else None)


class EventBatch(BaseModel):
    # Each event as for POST /events/; each is checked on its own.
    events: List[Dict[str, Any]] = Field(min_length=1, max_length=MAX_BATCH)


class BatchItem(BaseModel):
    index: int
    status: Literal["created", "duplicate", "rejected"]
    id: Optional[str] = None
    error: Optional[str] = None


class BatchResult(BaseModel):
    created: int
    duplicates: int
    rejected: int
    results: List[BatchItem]


def _first_error(error: ValidationError) -> str:
    first = error.errors()[0]
    field = ".".join(str(part) for part in first.get("loc", ()))
    return f"{field}: {first.get('msg')}" if field else str(first.get("msg"))


@router.post("/batch", response_model=BatchResult)
async def create_events(
    batch: EventBatch,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
):
    """
    Send up to 500 events at once (gzip the body with `Content-Encoding: gzip` for large
    batches). Each event is checked on its own: invalid ones are listed as rejected and the
    rest stored. Events with a `source` and `external_id` already received count as
    duplicates, so a batch can be sent again safely; so can a request with the same
    `Idempotency-Key`. `results` follows the order of `events`.
    """
    record, replay = await idempotency.begin(request, json.dumps(batch.events, sort_keys=True, default=str).encode())
    if replay:
        return JSONResponse(status_code=replay["status_code"], content=replay["content"], headers={"Idempotent-Replayed": "true"})
    results: List[BatchItem] = []
    try:
        for index, raw in enumerate(batch.events):
            try:
                event = EventCreate.model_validate(raw)
            except ValidationError as e:
                results.append(BatchItem(index=index, status="rejected", error=_first_error(e)))
                continue
            event_id, duplicate = await _store(event, background_tasks)
            results.append(BatchItem(index=index, status="duplicate" if duplicate else "created", id=event_id))
    except BaseException:
        await idempotency.abandon(record)
        raise
    result = BatchResult(
        created=sum(r.status == "created" for r in results), duplicates=sum(r.status == "duplicate" for r in results),
        rejected=sum(r.status == "rejected" for r in results), results=results,
    )
    content = jsonable_encoder(result)
    await idempotency.finish(record, 200, content)
    return content


class Reanalysis(BaseModel):
    # Only events whose analysis failed at or after this time; all failed ones when absent.
    failed_since: Optional[datetime] = None


class Requeued(BaseModel):
    queued: int = Field(description="How many events were queued to be analysed again")


@router.post("/reanalyse", response_model=Requeued)
async def reanalyse_failed(request: Request, body: Reanalysis, admin: User = Depends(require_admin)):
    """
    Queue every event whose analysis failed to be analysed again (administrators): after
    the core engine was unavailable for longer than the gateway keeps trying.
    """
    queued = await detection_pipeline.requeue(failed_since=body.failed_since)
    await audit.record("events.reanalyse", request, details={"queued": queued, "failed_since": body.failed_since})
    return {"queued": queued}


@router.post("/{event_id}/reanalyse", response_model=Event)
async def reanalyse_event(
    request: Request,
    background_tasks: BackgroundTasks,
    event_id: str = Path(..., title="The ID of the event to analyse again"),
    current_user: User = Depends(get_current_active_user),
):
    """Analyse an event again, such as one whose analysis failed. A threat it shows raises an alert once."""
    event_service = EventService()
    if not await event_service.get_event_by_id(event_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    if not await detection_pipeline.requeue([event_id]):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No core engine is configured, or the event is already being analysed")
    background_tasks.add_task(detection_pipeline.analyse_queued, event_id)
    await audit.record("events.reanalyse", request, target={"type": "event", "id": event_id})
    return await event_service.get_event_by_id(event_id)


@router.get("/{event_id}", response_model=Event)
async def get_event(
    event_id: str = Path(..., title="The ID of the event to get"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get a specific event by ID.
    """
    event_service = EventService()
    event = await event_service.get_event_by_id(event_id)

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found",
        )

    return event


@router.put("/{event_id}", response_model=Event)
async def update_event(
    event_update: EventUpdate,
    event_id: str = Path(..., title="The ID of the event to update"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Update an existing event.
    """
    event_service = EventService()
    updated_event = await event_service.update_event(event_id, event_update)

    if not updated_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found",
        )

    return updated_event


@router.get("/recent/", response_model=List[Event])
async def get_recent_events(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get most recent events.

    - **limit**: Maximum number of events to return
    """
    event_service = EventService()
    return await event_service.get_recent_events(limit)


@router.get("/timerange/", response_model=List[Event])
async def get_events_by_time_range(
    start_time: datetime,
    end_time: datetime,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get events within a specific time range.

    - **start_time**: Start of time range (ISO 8601 format)
    - **end_time**: End of time range (ISO 8601 format)
    - **limit**: Maximum number of events to return
    - **skip**: Number of events to skip (for pagination)
    """
    event_service = EventService()
    return await event_service.get_events_by_time_range(
        start_time, end_time, limit, skip
    )


@router.patch("/{event_id}/severity", response_model=Event)
async def set_event_severity(
    severity: str,
    event_id: str = Path(..., title="The ID of the event to update"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Set the severity of an event.

    - **severity**: New severity (critical, high, medium, low, info)
    """
    event_service = EventService()

    # Validate severity
    valid_severities = ["critical", "high", "medium", "low", "info"]
    if severity not in valid_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}",
        )

    result = await event_service.set_event_severity(event_id, severity)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found",
        )

    updated_event = await event_service.get_event_by_id(event_id)
    return updated_event


@router.post("/{event_id}/tags/{tag}")
async def add_tag_to_event(
    event_id: str = Path(..., title="The ID of the event"),
    tag: str = Path(..., title="The tag to add"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Add a tag to an event.
    """
    event_service = EventService()

    result = await event_service.add_tag_to_event(event_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found",
        )

    return {"status": "success", "message": f"Tag '{tag}' added to event {event_id}"}


@router.delete("/{event_id}/tags/{tag}")
async def remove_tag_from_event(
    event_id: str = Path(..., title="The ID of the event"),
    tag: str = Path(..., title="The tag to remove"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Remove a tag from an event.
    """
    event_service = EventService()

    result = await event_service.remove_tag_from_event(event_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found or tag '{tag}' not present",
        )

    return {
        "status": "success",
        "message": f"Tag '{tag}' removed from event {event_id}",
    }


@router.get("/search/", response_model=List[Event])
async def search_events(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """
    Search events by keyword in description.

    - **query**: Search term
    - **limit**: Maximum number of events to return
    - **skip**: Number of events to skip (for pagination)
    """
    event_service = EventService()
    return await event_service.search_events(query, limit, skip)
