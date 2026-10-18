"""Playbooks: what to do, step by step, when a kind of threat is found."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status

from api.routes.response import actor_of
from core.models.response import Playbook, PlaybookCreate, PlaybookRun, PlaybookRunResult, PlaybookUpdate
from core.models.user import User
from core.services import audit, playbooks
from core.services.response_actions import ActionError
from utils.security import get_current_active_user, require_admin

router = APIRouter()


def _found(playbook):
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    return playbook


@router.get("/", response_model=List[Playbook])
async def list_playbooks(current_user: User = Depends(get_current_active_user)):
    """Your organisation's playbooks, built-in ones first."""
    return await playbooks.list_playbooks()


@router.post("/", response_model=Playbook, status_code=status.HTTP_201_CREATED)
async def create_playbook(body: PlaybookCreate, request: Request, admin: User = Depends(require_admin)):
    """Add a playbook (administrators only)."""
    playbook = await playbooks.create(body.model_dump())
    audit.created(request, "playbook", str(playbook["_id"]), playbook["name"])
    return playbook


@router.get("/{playbook_id}", response_model=Playbook)
async def get_playbook(playbook_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    return _found(await playbooks.get(playbook_id))


@router.patch("/{playbook_id}", response_model=Playbook)
async def update_playbook(body: PlaybookUpdate, playbook_id: str = Path(...), admin: User = Depends(require_admin)):
    """Change a playbook, or turn it on or off (administrators only)."""
    return _found(await playbooks.update(playbook_id, body.model_dump(exclude_unset=True, exclude_none=True)))


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(playbook_id: str = Path(...), admin: User = Depends(require_admin)):
    """Delete a playbook of your own (administrators only). Built-in playbooks can be turned off instead."""
    if not await playbooks.delete(playbook_id):
        playbook = _found(await playbooks.get(playbook_id))
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"\"{playbook['name']}\" is built in: turn it off instead")


@router.post("/{playbook_id}/run", response_model=PlaybookRunResult)
async def run_playbook(body: PlaybookRun, request: Request, playbook_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """
    Run a playbook against a case now. Running it yourself is your decision, so its
    actions run at once (an API key's wait for approval, as do actions on protected
    accounts unless you are an administrator).
    """
    playbook = _found(await playbooks.get(playbook_id))
    try:
        return await playbooks.run(playbook, body.case_id, actor=actor_of(request))
    except ActionError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
