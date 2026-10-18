"""Cases: related alerts, grouped to be worked once."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from core.database.repositories.user_repository import UserRepository
from core.models.case import Case, CaseEvidence, CaseNote, CaseStatus, CaseUpdate, Priority
from core.models.user import User
from core.services import case_service
from utils.security import get_current_active_user

router = APIRouter()


def _actor(request: Request) -> dict:
    principal = getattr(request.state, "principal", None) or {}
    return {k: principal.get(k) for k in ("type", "id", "name")}


@router.get("/", response_model=List[Case])
async def list_cases(
    status_: Optional[List[CaseStatus]] = Query(None, alias="status", description="One or more statuses"),
    priority: Optional[Priority] = None,
    owner_id: Optional[str] = Query(None, description="A user id, or 'none' for unassigned cases"),
    open_only: bool = Query(False, description="Only open, investigating and contained cases"),
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """Cases, most recently active first. The list leaves out each case's timeline."""
    query: dict = {}
    if status_:
        query["status"] = {"$in": status_}
    elif open_only:
        query["status"] = {"$in": case_service.OPEN}
    if priority:
        query["priority"] = priority
    if owner_id:
        query["owner_id"] = None if owner_id == "none" else owner_id
    return await case_service.list_cases(query, limit, skip)


async def _found(case):
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return case


@router.get("/{case_id}", response_model=Case)
async def get_case(case_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """A case with its timeline, and an explanation of it in plain language."""
    return await _found(await case_service.get_case(case_id))


@router.patch("/{case_id}", response_model=Case)
async def update_case(
    update: CaseUpdate, request: Request, case_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """
    Change a case's status, priority, owner or title; each change is added to its
    timeline. Resolving, closing or marking it a false positive does the same to its
    alerts that are still open.
    """
    changes = update.model_dump(exclude_unset=True)
    if changes.get("owner_id") and not await UserRepository().find_by_id(changes["owner_id"]):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="No such user in your organisation")
    return await _found(await case_service.update_case(case_id, changes, _actor(request)))


@router.post("/{case_id}/notes", response_model=Case, status_code=status.HTTP_201_CREATED)
async def add_note(
    note: CaseNote, request: Request, case_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """Add a note to a case's timeline."""
    return await _found(await case_service.add_note(case_id, note.text, _actor(request)))


@router.get("/{case_id}/evidence", response_model=CaseEvidence)
async def case_evidence(case_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """The alerts and events behind a case, oldest first, and the entities involved."""
    return await _found(await case_service.evidence(case_id))
