"""Email notifications: what you are emailed about, and the delivery log."""
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from core.models.notification import Notification, NotificationPreferences, NotificationPreferencesUpdate, TestEmailResult
from core.models.user import User
from core.services import notifications
from utils.security import get_current_active_user, require_admin

router = APIRouter()


def _person(request: Request, current_user: User = Depends(get_current_active_user)) -> User:
    if (getattr(request.state, "principal", None) or {}).get("type") != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Notifications are for people, not API keys")
    return current_user


async def _preferences(user: User, values: dict) -> dict:
    return {**values, "email_configured": notifications.configured(), "address": user.email}


@router.get("/preferences", response_model=NotificationPreferences)
async def get_preferences(user: User = Depends(_person)):
    """What you are emailed about, and whether email is set up."""
    return await _preferences(user, await notifications.get_preferences(user.id))


@router.patch("/preferences", response_model=NotificationPreferences)
async def update_preferences(body: NotificationPreferencesUpdate, user: User = Depends(_person)):
    """Change what you are emailed about."""
    return await _preferences(user, await notifications.set_preferences(user.id, body.model_dump(exclude_none=True)))


@router.post("/test", response_model=TestEmailResult)
async def send_test_email(user: User = Depends(_person)):
    """Send yourself a test email now, to check that email works."""
    error = await notifications.send_test(user.email)
    return {"sent": error is None, "error": error}


@router.get("/", response_model=List[Notification])
async def delivery_log(
    status_: Optional[Literal["queued", "sending", "sent", "failed", "skipped"]] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    admin: User = Depends(require_admin),
):
    """Every email your organisation's people were sent or not sent, newest first (administrators only)."""
    return await notifications.log({"status": status_} if status_ else {}, limit, skip)
