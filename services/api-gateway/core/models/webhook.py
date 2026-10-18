from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, Field, field_validator

from core.models.common import IdString


def _known(events: List[str]) -> List[str]:
    from core.services.webhooks import EVENTS

    unknown = [e for e in events if e != "*" and e not in EVENTS]
    if unknown:
        raise ValueError(f"Unknown events: {', '.join(unknown)}")
    return events


class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=8, max_length=2000)
    # Event types, or "*" for all of them.
    events: List[str] = Field(min_length=1, max_length=20)

    _check_events = field_validator("events")(_known)


class WebhookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    url: Optional[str] = Field(None, min_length=8, max_length=2000)
    events: Optional[List[str]] = Field(None, min_length=1, max_length=20)
    enabled: Optional[bool] = None

    @field_validator("events")
    @classmethod
    def _events(cls, value):
        return _known(value) if value is not None else value


class Webhook(BaseModel):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    name: str
    url: str
    events: List[str]
    enabled: bool
    created_at: datetime
    created_by: Dict[str, Any]
    last_delivery_at: Optional[datetime] = None
    # ok, or failing (the last attempt did not get through)
    last_status: Optional[str] = None


class WebhookWithSecret(Webhook):
    # For checking the UTDRS-Signature header. Shown only this once.
    signing_secret: str


class SigningSecret(BaseModel):
    signing_secret: str


class EventType(BaseModel):
    name: str
    description: str


class Delivery(BaseModel):
    id: str = Field(validation_alias=AliasChoices("_id", "id"))
    webhook_id: str
    event: str
    payload: Dict[str, Any]
    # queued, sending, delivered or failed (after a day of retries)
    status: str
    attempts: int
    response_status: Optional[int] = None
    error: Optional[str] = None
    created_at: datetime
    next_attempt_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
