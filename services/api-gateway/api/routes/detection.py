from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional, Dict, Any
from core.models.user import User
from core.models.detection import DetectionRule, DetectionRuleCreate, DetectionRuleUpdate
from core.services.detection_service import DetectionService
from utils.security import get_current_active_user

router = APIRouter()

@router.get("/", response_model=Dict[str, Any])
async def get_detection_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get overall detection system status.
    """
    detection_service = DetectionService()
    return await detection_service.get_detection_status()

@router.get("/rules", response_model=List[DetectionRule])
async def get_rules(
    rule_type: Optional[str] = None,
    detection_source: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get detection rules with optional filtering.
    
    - **rule_type**: Filter by rule type
    - **detection_source**: Filter by detection source
    - **severity**: Filter by severity
    - **status**: Filter by status
    - **tag**: Filter by tag
    - **limit**: Maximum number of rules to return
    - **skip**: Number of rules to skip (for pagination)
    """
    detection_service = DetectionService()
    
    if rule_type:
        return await detection_service.get_rules_by_type(rule_type, limit, skip)
    elif detection_source:
        return await detection_service.get_rules_by_source(detection_source, limit, skip)
    elif severity:
        return await detection_service.get_rules_by_severity(severity, limit, skip)
    elif status:
        return await detection_service.get_rules_by_status(status, limit, skip)
    elif tag:
        return await detection_service.get_rules_by_tag(tag, limit, skip)
    else:
        return await detection_service.get_rules(limit, skip)

@router.post("/rules", response_model=DetectionRule, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: DetectionRuleCreate,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new detection rule.
    """
    detection_service = DetectionService()
    rule_id = await detection_service.create_rule(rule, current_user.id)
    
    created_rule = await detection_service.get_rule_by_id(rule_id)
    if not created_rule:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create detection rule"
        )
    
    return created_rule

@router.get("/rules/{rule_id}", response_model=DetectionRule)
async def get_rule(
    rule_id: str = Path(..., title="The ID of the rule to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific detection rule by ID.
    """
    detection_service = DetectionService()
    rule = await detection_service.get_rule_by_id(rule_id)
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found"
        )
    
    return rule

@router.put("/rules/{rule_id}", response_model=DetectionRule)
async def update_rule(
    rule_update: DetectionRuleUpdate,
    rule_id: str = Path(..., title="The ID of the rule to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update an existing detection rule.
    """
    detection_service = DetectionService()
    updated_rule = await detection_service.update_rule(rule_id, rule_update, current_user.id)
    
    if not updated_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found"
        )
    
    return updated_rule

@router.patch("/rules/{rule_id}/status", response_model=DetectionRule)
async def update_rule_status(
    status: str,
    rule_id: str = Path(..., title="The ID of the rule to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update the status of a detection rule.
    
    - **status**: New status (enabled, disabled, testing)
    """
    detection_service = DetectionService()
    
    # Validate status
    valid_statuses = ["enabled", "disabled", "testing"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    result = await detection_service.update_rule_status(rule_id, status, current_user.id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found"
        )
    
    updated_rule = await detection_service.get_rule_by_id(rule_id)
    return updated_rule

@router.get("/rules/name/{name}", response_model=DetectionRule)
async def get_rule_by_name(
    name: str = Path(..., title="The name of the rule to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a detection rule by name.
    """
    detection_service = DetectionService()
    rule = await detection_service.get_rule_by_name(name)
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with name '{name}' not found"
        )
    
    return rule

@router.post("/rules/{rule_id}/tags/{tag}")
async def add_tag_to_rule(
    rule_id: str = Path(..., title="The ID of the rule"),
    tag: str = Path(..., title="The tag to add"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a tag to a detection rule.
    """
    detection_service = DetectionService()
    
    result = await detection_service.add_tag_to_rule(rule_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' added to detection rule {rule_id}"}

@router.delete("/rules/{rule_id}/tags/{tag}")
async def remove_tag_from_rule(
    rule_id: str = Path(..., title="The ID of the rule"),
    tag: str = Path(..., title="The tag to remove"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Remove a tag from a detection rule.
    """
    detection_service = DetectionService()
    
    result = await detection_service.remove_tag_from_rule(rule_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found or tag '{tag}' not present"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' removed from detection rule {rule_id}"}

@router.patch("/rules/{rule_id}/metrics")
async def update_rule_performance_metrics(
    metrics: Dict[str, Any],
    rule_id: str = Path(..., title="The ID of the rule"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update performance metrics for a detection rule.
    
    - **metrics**: Dictionary of performance metrics
    """
    detection_service = DetectionService()
    
    result = await detection_service.update_rule_performance_metrics(rule_id, metrics)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found"
        )
    
    return {"status": "success", "message": f"Updated performance metrics for detection rule {rule_id}"}

@router.get("/rules/search/", response_model=List[DetectionRule])
async def search_rules(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search detection rules by keyword in name, description, or logic.
    
    - **query**: Search term
    - **limit**: Maximum number of rules to return
    - **skip**: Number of rules to skip (for pagination)
    """
    detection_service = DetectionService()
    return await detection_service.search_rules(query, limit, skip)