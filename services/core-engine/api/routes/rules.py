from fastapi import APIRouter, Depends, HTTPException, status, Body
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from core.rules.rule_loader import RuleManager

router = APIRouter()

# Initialize rule manager lazily
_rule_manager = None

def get_rule_manager():
    global _rule_manager
    if _rule_manager is None:
        _rule_manager = RuleManager()
    return _rule_manager

class DetectionRule(BaseModel):
    name: str
    description: str
    rule_type: str
    detection: Dict[str, Any]
    enabled: bool = True
    severity: str
    tags: List[str] = []

@router.get("/", response_model=List[DetectionRule])
async def get_rules(
    rule_type: Optional[str] = None, 
    enabled: Optional[bool] = None,
    limit: int = 100, 
    skip: int = 0
):
    '''Get detection rules based on filters.'''
    rule_manager = get_rule_manager()
    filters = {}
    if rule_type:
        filters["rule_type"] = rule_type
    if enabled is not None:
        filters["enabled"] = enabled
        
    rules = await rule_manager.get_rules(filters, limit, skip)
    return rules

@router.get("/{rule_id}", response_model=DetectionRule)
async def get_rule(rule_id: str):
    '''Get a specific rule by ID.'''
    rule_manager = get_rule_manager()
    rule = await rule_manager.get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    return rule

@router.post("/", response_model=DetectionRule)
async def create_rule(rule: DetectionRule):
    '''Create a new detection rule.'''
    rule_manager = get_rule_manager()
    created_rule = await rule_manager.create_rule(rule.dict())
    return created_rule

@router.put("/{rule_id}", response_model=DetectionRule)
async def update_rule(rule_id: str, rule: DetectionRule):
    '''Update an existing detection rule.'''
    rule_manager = get_rule_manager()
    updated_rule = await rule_manager.update_rule(rule_id, rule.dict())
    if not updated_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    return updated_rule

@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: str):
    '''Delete a detection rule.'''
    rule_manager = get_rule_manager()
    deleted = await rule_manager.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )