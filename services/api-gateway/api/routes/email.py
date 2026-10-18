"""Checking an email for phishing."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.routes.response import actor_of
from core.models.user import User
from core.services import m365, m365_email
from utils.security import get_current_active_user

router = APIRouter()


class EmailCheck(BaseModel):
    # The mailbox it was delivered to, and its Internet message id (the Message-ID header).
    recipient: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    internet_message_id: str = Field(min_length=3, max_length=1000)


class EmailCheckResult(BaseModel):
    event_id: str
    alert_id: str | None = None
    # Checked before: the earlier result is returned, and nothing is fetched again.
    already_checked: bool


@router.post("/check", response_model=EmailCheckResult)
async def check_email(body: EmailCheck, request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Check a delivered email for phishing: UTDRS reads its headers, sender, links and
    attachments from the recipient's mailbox, and the engine judges it. The result is an
    `email` event, and an alert if it looks malicious; the body is not kept.
    """
    try:
        return await m365_email.analyse(body.recipient, body.internet_message_id, reported_by=actor_of(request))
    except m365.NotConnected as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except m365_email.MessageNotFound as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
