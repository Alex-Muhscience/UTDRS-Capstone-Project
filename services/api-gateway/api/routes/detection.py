from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request, status

from core.models.detection import (
    DetectionRule,
    DetectionRuleCreate,
    DetectionRuleUpdate,
    DetectionStatus,
    RuleTestRequest,
    RuleTestRun,
    RuleVersion,
)
from core.models.user import User
from core.services.audit import created
from core.services import rule_tests, rule_versions
from core.services.detection_service import DetectionService
from core.services.rule_compiler import RuleSyntaxError, compile_logic
from core.services.rule_sync import sync_rules
from utils.security import get_current_active_user, require_admin

router = APIRouter()


def _check_logic(logic: Optional[str]) -> None:
    """Refuse malformed logic. Logic the engine cannot run yet is allowed, and kept but not run."""
    if logic is None:
        return
    try:
        compile_logic(logic)
    except RuleSyntaxError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"Rule logic: {e}")
    except ValueError:
        pass


@router.get("/", response_model=DetectionStatus)
async def get_detection_status(current_user: User = Depends(get_current_active_user)):
    """
    Rule counts by status, and whether the core detection engine is configured and reachable.
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
    current_user: User = Depends(get_current_active_user),
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
        return await detection_service.get_rules_by_source(
            detection_source, limit, skip
        )
    elif severity:
        return await detection_service.get_rules_by_severity(severity, limit, skip)
    elif status:
        return await detection_service.get_rules_by_status(status, limit, skip)
    elif tag:
        return await detection_service.get_rules_by_tag(tag, limit, skip)
    else:
        return await detection_service.get_rules(limit, skip)


def _check_tests(logic: str, test_cases: list) -> None:
    """Refuse a rule whose test cases fail (when the engine can run its logic)."""
    if not test_cases:
        return
    cases = [c.model_dump() if hasattr(c, "model_dump") else c for c in test_cases]
    problem = rule_tests.failures(rule_tests.run(logic, cases))
    if problem:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"Not saved: {problem}")


@router.post("/rules/test", response_model=RuleTestRun)
async def test_logic(body: RuleTestRequest, current_user: User = Depends(get_current_active_user)):
    """Run test cases against logic, before saving it: what the core engine would match."""
    _check_logic(body.logic)
    return rule_tests.run(body.logic, [c.model_dump() for c in body.test_cases])


@router.post(
    "/rules", response_model=DetectionRule, status_code=status.HTTP_201_CREATED
)
async def create_rule(
    rule: DetectionRuleCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
):
    """
    Create a new detection rule. Malformed logic answers 422. While the rule is enabled
    and the engine can run its logic (see `engine` in the response), the core engine runs it.
    """
    _check_logic(rule.logic)
    _check_tests(rule.logic, rule.test_cases)
    detection_service = DetectionService()
    rule_id = await detection_service.create_rule(rule, current_user.id)

    created_rule = await detection_service.get_rule_by_id(rule_id)
    if not created_rule:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create detection rule",
        )
    created(request, "rule", rule_id, rule.name)
    background_tasks.add_task(sync_rules)

    return created_rule


@router.get("/rules/{rule_id}", response_model=DetectionRule)
async def get_rule(
    rule_id: str = Path(..., title="The ID of the rule to get"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get a specific detection rule by ID.
    """
    detection_service = DetectionService()
    rule = await detection_service.get_rule_by_id(rule_id)

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found",
        )

    return rule


@router.put("/rules/{rule_id}", response_model=DetectionRule)
async def update_rule(
    rule_update: DetectionRuleUpdate,
    background_tasks: BackgroundTasks,
    rule_id: str = Path(..., title="The ID of the rule to update"),
    current_user: User = Depends(require_admin),
):
    """
    Update an existing detection rule. Malformed logic answers 422. The core engine is
    updated straight after.
    """
    _check_logic(rule_update.logic)
    detection_service = DetectionService()
    if rule_update.logic is not None or rule_update.test_cases is not None:
        existing = await detection_service.get_rule_by_id(rule_id) or {}
        _check_tests(rule_update.logic if rule_update.logic is not None else existing.get("logic", ""),
                     rule_update.test_cases if rule_update.test_cases is not None else existing.get("test_cases") or [])
    updated_rule = await detection_service.update_rule(
        rule_id, rule_update, current_user.id
    )

    if not updated_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found",
        )

    background_tasks.add_task(sync_rules)
    return updated_rule


@router.patch("/rules/{rule_id}/status", response_model=DetectionRule)
async def update_rule_status(
    background_tasks: BackgroundTasks,
    new_status: str = Query(..., alias="status"),
    rule_id: str = Path(..., title="The ID of the rule to update"),
    current_user: User = Depends(require_admin),
):
    """
    Update the status of a detection rule.

    - **status**: New status (enabled, disabled, testing)
    """
    detection_service = DetectionService()

    # Validate status
    valid_statuses = ["enabled", "disabled", "testing"]
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    if new_status == "enabled":
        existing = await detection_service.get_rule_by_id(rule_id) or {}
        _check_tests(existing.get("logic", ""), existing.get("test_cases") or [])
    result = await detection_service.update_rule_status(
        rule_id, new_status, current_user.id
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found",
        )

    updated_rule = await detection_service.get_rule_by_id(rule_id)
    background_tasks.add_task(sync_rules)
    return updated_rule


@router.get("/rules/name/{name}", response_model=DetectionRule)
async def get_rule_by_name(
    name: str = Path(..., title="The name of the rule to get"),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get a detection rule by name.
    """
    detection_service = DetectionService()
    rule = await detection_service.get_rule_by_name(name)

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with name '{name}' not found",
        )

    return rule


@router.post("/rules/{rule_id}/tags/{tag}")
async def add_tag_to_rule(
    background_tasks: BackgroundTasks,
    rule_id: str = Path(..., title="The ID of the rule"),
    tag: str = Path(..., title="The tag to add"),
    current_user: User = Depends(require_admin),
):
    """
    Add a tag to a detection rule.
    """
    detection_service = DetectionService()

    result = await detection_service.add_tag_to_rule(rule_id, tag, current_user.id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found",
        )

    # Technique tags (T1059.001) go to the engine with the rule.
    background_tasks.add_task(sync_rules)
    return {
        "status": "success",
        "message": f"Tag '{tag}' added to detection rule {rule_id}",
    }


@router.delete("/rules/{rule_id}/tags/{tag}")
async def remove_tag_from_rule(
    background_tasks: BackgroundTasks,
    rule_id: str = Path(..., title="The ID of the rule"),
    tag: str = Path(..., title="The tag to remove"),
    current_user: User = Depends(require_admin),
):
    """
    Remove a tag from a detection rule.
    """
    detection_service = DetectionService()

    result = await detection_service.remove_tag_from_rule(rule_id, tag, current_user.id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID {rule_id} not found or tag '{tag}' not present",
        )

    # Technique tags (T1059.001) go to the engine with the rule.
    background_tasks.add_task(sync_rules)
    return {
        "status": "success",
        "message": f"Tag '{tag}' removed from detection rule {rule_id}",
    }


@router.patch("/rules/{rule_id}/metrics")
async def update_rule_performance_metrics(
    metrics: Dict[str, Any],
    rule_id: str = Path(..., title="The ID of the rule"),
    current_user: User = Depends(require_admin),
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
            detail=f"Detection rule with ID {rule_id} not found",
        )

    return {
        "status": "success",
        "message": f"Updated performance metrics for detection rule {rule_id}",
    }


@router.get("/rules/search/", response_model=List[DetectionRule])
async def search_rules(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """
    Search detection rules by keyword in name, description, or logic.

    - **query**: Search term
    - **limit**: Maximum number of rules to return
    - **skip**: Number of rules to skip (for pagination)
    """
    detection_service = DetectionService()
    return await detection_service.search_rules(query, limit, skip)


@router.post("/rules/{rule_id}/test", response_model=RuleTestRun)
async def test_rule(rule_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """Run a saved rule's test cases."""
    rule = await DetectionService().get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Detection rule with ID {rule_id} not found")
    return rule_tests.run(rule.get("logic", ""), rule.get("test_cases") or [])


@router.get("/rules/{rule_id}/versions", response_model=List[RuleVersion])
async def rule_history(rule_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """Every version of a rule, newest first: what it was, who changed it, and when."""
    if not await DetectionService().get_rule_by_id(rule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Detection rule with ID {rule_id} not found")
    return await rule_versions.history(rule_id)


@router.post("/rules/{rule_id}/versions/{version}/restore", response_model=DetectionRule)
async def restore_rule_version(
    background_tasks: BackgroundTasks,
    rule_id: str = Path(...),
    version: int = Path(..., ge=1),
    current_user: User = Depends(require_admin),
):
    """
    Make a rule what it was at an earlier version (administrators). This makes a new
    version: history is never rewritten. Its test cases must still pass.
    """
    found = await rule_versions.get(rule_id, version)
    if not found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Version {version} of this rule not found")
    snapshot = {k: v for k, v in found["rule"].items() if k in rule_versions.FIELDS}
    snapshot["test_cases"] = snapshot.get("test_cases") or []
    _check_tests(snapshot.get("logic", ""), snapshot["test_cases"])
    restored = await DetectionService().update_rule(rule_id, DetectionRuleUpdate(**snapshot), current_user.id, change=f"restored from version {version}")
    if not restored:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Detection rule with ID {rule_id} not found")
    background_tasks.add_task(sync_rules)
    return restored
