from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional
from core.models.user import User
from core.models.alert import Alert, AlertCreate, AlertUpdate
from core.services.alert_service import AlertService
from utils.security import get_current_active_user

router = APIRouter()

@router.get("/", response_model=List[Alert])
async def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all alerts with optional filtering.
    
    - **status**: Filter by alert status (open, in_progress, resolved, closed, false_positive)
    - **severity**: Filter by alert severity (critical, high, medium, low, info)
    - **limit**: Maximum number of alerts to return
    - **skip**: Number of alerts to skip (for pagination)
    """
    alert_service = AlertService()
    
    if status:
        return await alert_service.get_alerts_by_status(status, limit, skip)
    elif severity:
        return await alert_service.get_alerts_by_severity(severity, limit, skip)
    else:
        return await alert_service.get_alerts(limit, skip)

@router.post("/", response_model=Alert, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert: AlertCreate,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new alert.
    """
    alert_service = AlertService()
    alert_id = await alert_service.create_alert(alert, current_user.id)
    
    created_alert = await alert_service.get_alert_by_id(alert_id)
    if not created_alert:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create alert"
        )
    
    return created_alert

@router.get("/{alert_id}", response_model=Alert)
async def get_alert(
    alert_id: str = Path(..., title="The ID of the alert to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific alert by ID.
    """
    alert_service = AlertService()
    alert = await alert_service.get_alert_by_id(alert_id)
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return alert

@router.put("/{alert_id}", response_model=Alert)
async def update_alert(
    alert_update: AlertUpdate,
    alert_id: str = Path(..., title="The ID of the alert to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update an existing alert.
    """
    alert_service = AlertService()
    updated_alert = await alert_service.update_alert(alert_id, alert_update, current_user.id)
    
    if not updated_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return updated_alert

@router.patch("/{alert_id}/status", response_model=Alert)
async def update_alert_status(
    status: str,
    notes: Optional[str] = None,
    alert_id: str = Path(..., title="The ID of the alert to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update the status of an alert.
    
    - **status**: New status (open, in_progress, resolved, closed, false_positive)
    - **notes**: Optional notes about the status change
    """
    alert_service = AlertService()
    
    # Validate status
    valid_statuses = ["open", "in_progress", "resolved", "closed", "false_positive"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    result = await alert_service.update_alert_status(alert_id, status, notes)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    updated_alert = await alert_service.get_alert_by_id(alert_id)
    return updated_alert

@router.patch("/{alert_id}/assign", response_model=Alert)
async def assign_alert(
    assigned_to: str,
    alert_id: str = Path(..., title="The ID of the alert to assign"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Assign an alert to a user.
    
    - **assigned_to**: User ID to assign the alert to
    """
    alert_service = AlertService()
    
    result = await alert_service.assign_alert(alert_id, assigned_to)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    updated_alert = await alert_service.get_alert_by_id(alert_id)
    return updated_alert

@router.get("/assigned/{user_id}", response_model=List[Alert])
async def get_alerts_by_assignee(
    user_id: str = Path(..., title="The ID of the user"),
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get alerts assigned to a specific user.
    
    - **user_id**: ID of the user to get alerts for
    - **limit**: Maximum number of alerts to return
    - **skip**: Number of alerts to skip (for pagination)
    """
    alert_service = AlertService()
    return await alert_service.get_alerts_assigned_to_user(user_id, limit, skip)

@router.patch("/{alert_id}/events/{event_id}")
async def add_event_to_alert(
    alert_id: str = Path(..., title="The ID of the alert"),
    event_id: str = Path(..., title="The ID of the event to add"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Add an event to an alert.
    """
    alert_service = AlertService()
    
    result = await alert_service.add_event_to_alert(alert_id, event_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} or Event with ID {event_id} not found"
        )
    
    return {"status": "success", "message": f"Event {event_id} added to alert {alert_id}"}

@router.post("/{alert_id}/tags/{tag}")
async def add_tag_to_alert(
    alert_id: str = Path(..., title="The ID of the alert"),
    tag: str = Path(..., title="The tag to add"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a tag to an alert.
    """
    alert_service = AlertService()
    
    result = await alert_service.add_tag_to_alert(alert_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' added to alert {alert_id}"}

@router.delete("/{alert_id}/tags/{tag}")
async def remove_tag_from_alert(
    alert_id: str = Path(..., title="The ID of the alert"),
    tag: str = Path(..., title="The tag to remove"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Remove a tag from an alert.
    """
    alert_service = AlertService()
    
    result = await alert_service.remove_tag_from_alert(alert_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found or tag '{tag}' not present"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' removed from alert {alert_id}"}

@router.get("/search/", response_model=List[Alert])
async def search_alerts(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search alerts by keyword in title or description.
    
    - **query**: Search term
    - **limit**: Maximum number of alerts to return
    - **skip**: Number of alerts to skip (for pagination)
    """
    alert_service = AlertService()
    return await alert_service.search_alerts(query, limit, skip)