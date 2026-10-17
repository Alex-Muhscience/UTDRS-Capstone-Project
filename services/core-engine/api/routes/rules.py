from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from typing import List, Literal, Optional, Dict, Any
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
    # "gateway" for rules managed through the gateway; absent for built-in rules.
    source: Optional[str] = None
    source_id: Optional[str] = None

class ManagedRule(BaseModel):
    source_id: str
    name: str
    description: str = ""
    rule_type: Literal["signature"] = "signature"
    detection: Dict[str, Any]
    enabled: bool = True
    severity: str
    tags: List[str] = []
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []


class ManagedRules(BaseModel):
    rules: List[ManagedRule]


class ManagedRulesResult(BaseModel):
    stored: int
    removed: int


@router.put("/managed/{source}", response_model=ManagedRulesResult)
async def replace_managed_rules(source: str, body: ManagedRules, tenant_id: str = Query(..., min_length=1)):
    '''
    Replace every rule another service manages (the API gateway's rules, edited in the
    dashboard) for one organisation (`tenant_id`) with this list. Rules are matched by
    source_id; that organisation's rules not listed are removed. Built-in rules, and other
    organisations' rules, are left alone.
    '''
    try:
        return await get_rule_manager().replace_managed_rules(
            source, [rule.model_dump() for rule in body.rules], tenant_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))


@router.get("/", response_model=List[DetectionRule])
async def get_rules(
    rule_type: Optional[str] = None, 
    enabled: Optional[bool] = None,
    source: Optional[str] = None,
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
    if source == "builtin":
        filters["source"] = {"$exists": False}
    elif source:
        filters["source"] = source
        
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
    created_rule = await rule_manager.create_rule(rule.model_dump())
    return created_rule

@router.put("/{rule_id}", response_model=DetectionRule)
async def update_rule(rule_id: str, rule: DetectionRule):
    '''Update an existing detection rule.'''
    rule_manager = get_rule_manager()
    updated_rule = await rule_manager.update_rule(rule_id, rule.model_dump())
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