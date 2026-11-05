"""Your notifications centre: what needs your attention, newest first."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from core.models.user import User
from core.services import inbox
from utils.security import get_current_active_user

router = APIRouter()


class InboxItem(BaseModel):
    id: str
    # alert, case, approval, action_failed, action_done, report, connector, alert_assigned, case_assigned
    kind: str
    title: str
    body: str = ""
    # Where in the dashboard it is about.
    link: Optional[str] = None
    severity: Optional[str] = None
    target: Optional[Dict[str, Any]] = None
    created_at: datetime
    read: bool


class Inbox(BaseModel):
    items: List[InboxItem]
    has_more: bool
    unread: int


class Unread(BaseModel):
    unread: int


class MarkRead(BaseModel):
    # The items to mark read; leave out to mark everything read.
    ids: Optional[List[str]] = Field(None, max_length=200)


async def _person(request: Request, current_user: User = Depends(get_current_active_user)) -> User:
    if (getattr(request.state, "principal", None) or {}).get("type") != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API keys have no inbox")
    return current_user


@router.get("", response_model=Inbox)
async def list_inbox(unread_only: bool = False, before: Optional[str] = None, limit: int = Query(30, ge=1, le=100), person: User = Depends(_person)):
    """Your notifications, newest first. Page with `before` (the last id you have)."""
    return await inbox.list_for(person.id, unread_only, before, limit)


@router.get("/unread", response_model=Unread)
async def unread(person: User = Depends(_person)):
    """How many of your notifications are unread."""
    return {"unread": await inbox.unread(person.id)}


@router.post("/read", response_model=Unread)
async def mark_read(body: MarkRead, person: User = Depends(_person)):
    """Mark notifications read: those named, or all of them."""
    await inbox.mark_read(person.id, body.ids)
    return {"unread": await inbox.unread(person.id)}
