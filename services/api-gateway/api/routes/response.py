"""Response actions: what UTDRS can do about a threat, and the approvals they wait for."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from core.models.response import Action, ActionDecision, ActionRequest, ActionStatus, ActionType, ResponseSettings, ResponseSettingsUpdate
from core.models.user import User
from core.services import audit, connectors, response_actions
from core.services.response_actions import ActionError, NotConnected, Refused
from utils.security import get_current_active_user, require_admin

router = APIRouter()


def actor_of(request: Request) -> dict:
    principal = getattr(request.state, "principal", None) or {}
    return {k: principal.get(k) for k in ("type", "id", "name", "role") if principal.get(k)}


def _person(request: Request) -> dict:
    actor = actor_of(request)
    if actor.get("type") != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a person can approve, reject or undo an action")
    return actor


def _refused(error: ActionError, default: int = status.HTTP_409_CONFLICT) -> HTTPException:
    code = status.HTTP_403_FORBIDDEN if isinstance(error, Refused) else status.HTTP_409_CONFLICT if isinstance(error, NotConnected) else default
    return HTTPException(status_code=code, detail=str(error))


def _found(action):
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    return action


@router.get("/actions/types", response_model=List[ActionType])
async def action_types(current_user: User = Depends(get_current_active_user)):
    """The actions UTDRS can take, and whether the service each needs is connected."""
    return [{**a, "connected": await connectors.connected(a["connector"])} for a in response_actions.catalogue()]


@router.get("/actions", response_model=List[Action])
async def list_actions(
    status_: Optional[List[ActionStatus]] = Query(None, alias="status"),
    case_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """Actions, newest first: `status=pending` for those waiting for a decision."""
    query: dict = {}
    if status_:
        query["status"] = {"$in": status_}
    if case_id:
        query["case_id"] = case_id
    return await response_actions.list_actions(query, limit, skip)


@router.post("/actions", response_model=Action, status_code=status.HTTP_201_CREATED)
async def request_action(body: ActionRequest, request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Take an action now. A person's request runs at once, except on a protected account,
    which needs an administrator; a request through an API key waits for a person's
    approval. The response says what happened (`status`).
    """
    try:
        action = await response_actions.request(body.action, body.target.model_dump(), body.params, actor=actor_of(request), case_id=body.case_id)
    except ActionError as e:
        raise _refused(e, status.HTTP_422_UNPROCESSABLE_CONTENT)
    audit.created(request, "action", action["id"], action["label"])
    return action


@router.get("/actions/{action_id}", response_model=Action)
async def get_action(action_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    return _found(await response_actions.get(action_id))


@router.post("/actions/{action_id}/approve", response_model=Action)
async def approve_action(request: Request, action_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """Approve an action waiting for a decision; it runs at once."""
    try:
        return _found(await response_actions.approve(action_id, _person(request)))
    except ActionError as e:
        raise _refused(e)


@router.post("/actions/{action_id}/reject", response_model=Action)
async def reject_action(
    request: Request, body: ActionDecision = ActionDecision(), action_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """Decide not to take an action waiting for a decision."""
    try:
        return _found(await response_actions.reject(action_id, _person(request), body.reason))
    except ActionError as e:
        raise _refused(e)


@router.post("/actions/{action_id}/undo", response_model=Action)
async def undo_action(request: Request, action_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """Undo an action that ran, where it can be undone. Returns the action that undid it."""
    try:
        return _found(await response_actions.undo(action_id, _person(request)))
    except ActionError as e:
        raise _refused(e)


@router.get("/settings", response_model=ResponseSettings)
async def get_settings(current_user: User = Depends(get_current_active_user)):
    """How far playbooks may act on their own in your organisation."""
    return await response_actions.get_settings()


@router.patch("/settings", response_model=ResponseSettings)
async def update_settings(body: ResponseSettingsUpdate, admin: User = Depends(require_admin)):
    """Change the response mode, the hourly limit or the protected accounts (administrators only)."""
    return await response_actions.update_settings(body.model_dump(exclude_unset=True, exclude_none=True))
