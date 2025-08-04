from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional
from datetime import datetime
from core.models.user import User
from core.models.event import Event, EventCreate, EventUpdate
from core.services.event_service import EventService
from utils.security import get_current_active_user

router = APIRouter()

@router.get("/", response_model=List[Event])
async def get_events(
    event_type: Optional[str] = None,
    asset_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
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

@router.post("/", response_model=Event, status_code=status.HTTP_201_CREATED)
async def create_event(
    event: EventCreate,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new event.
    """
    event_service = EventService()
    event_id = await event_service.create_event(event)
    
    created_event = await event_service.get_event_by_id(event_id)
    if not created_event:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create event"
        )
    
    return created_event

@router.get("/{event_id}", response_model=Event)
async def get_event(
    event_id: str = Path(..., title="The ID of the event to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific event by ID.
    """
    event_service = EventService()
    event = await event_service.get_event_by_id(event_id)
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found"
        )
    
    return event

@router.put("/{event_id}", response_model=Event)
async def update_event(
    event_update: EventUpdate,
    event_id: str = Path(..., title="The ID of the event to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update an existing event.
    """
    event_service = EventService()
    updated_event = await event_service.update_event(event_id, event_update)
    
    if not updated_event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found"
        )
    
    return updated_event

@router.get("/recent/", response_model=List[Event])
async def get_recent_events(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_active_user)
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
    current_user: User = Depends(get_current_active_user)
):
    """
    Get events within a specific time range.
    
    - **start_time**: Start of time range (ISO 8601 format)
    - **end_time**: End of time range (ISO 8601 format)
    - **limit**: Maximum number of events to return
    - **skip**: Number of events to skip (for pagination)
    """
    event_service = EventService()
    return await event_service.get_events_by_time_range(start_time, end_time, limit, skip)

@router.patch("/{event_id}/severity", response_model=Event)
async def set_event_severity(
    severity: str,
    event_id: str = Path(..., title="The ID of the event to update"),
    current_user: User = Depends(get_current_active_user)
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
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )
    
    result = await event_service.set_event_severity(event_id, severity)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found"
        )
    
    updated_event = await event_service.get_event_by_id(event_id)
    return updated_event

@router.post("/{event_id}/tags/{tag}")
async def add_tag_to_event(
    event_id: str = Path(..., title="The ID of the event"),
    tag: str = Path(..., title="The tag to add"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a tag to an event.
    """
    event_service = EventService()
    
    result = await event_service.add_tag_to_event(event_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' added to event {event_id}"}

@router.delete("/{event_id}/tags/{tag}")
async def remove_tag_from_event(
    event_id: str = Path(..., title="The ID of the event"),
    tag: str = Path(..., title="The tag to remove"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Remove a tag from an event.
    """
    event_service = EventService()
    
    result = await event_service.remove_tag_from_event(event_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with ID {event_id} not found or tag '{tag}' not present"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' removed from event {event_id}"}

@router.get("/search/", response_model=List[Event])
async def search_events(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search events by keyword in description.
    
    - **query**: Search term
    - **limit**: Maximum number of events to return
    - **skip**: Number of events to skip (for pagination)
    """
    event_service = EventService()
    return await event_service.search_events(query, limit, skip)