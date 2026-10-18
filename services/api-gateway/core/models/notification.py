from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import AliasChoices, BaseModel, Field

from core.models.common import IdString

NewCases = Literal["critical", "high", "medium", "low", "info", "off"]
ActionsWanted = Literal["all", "failed", "off"]


class NotificationPreferences(BaseModel):
    """What you are emailed about."""

    email: bool
    # The lowest priority of new case to hear about, or "off".
    new_cases: NewCases
    # Actions waiting for a decision you can make.
    approvals: bool
    # Actions that ran: all of them, only those that failed, or none.
    actions: ActionsWanted
    # The monthly report, when it is ready (administrators only).
    reports: bool = True
    # Whether this UTDRS can send email at all, and where yours goes.
    email_configured: bool = False
    address: Optional[str] = None


class NotificationPreferencesUpdate(BaseModel):
    email: Optional[bool] = None
    new_cases: Optional[NewCases] = None
    approvals: Optional[bool] = None
    actions: Optional[ActionsWanted] = None
    reports: Optional[bool] = None


class Notification(BaseModel):
    """One email, as the delivery log shows it."""

    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    kind: str
    user_id: str
    email: str
    subject: str
    link: Optional[str] = None
    about: Optional[Dict[str, Any]] = None
    # queued, sending, sent, failed (after every retry) or skipped (with the reason)
    status: str
    error: Optional[str] = None
    attempts: int
    created_at: datetime
    sent_at: Optional[datetime] = None


class TestEmailResult(BaseModel):
    sent: bool
    error: Optional[str] = None
