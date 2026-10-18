from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, Field


class RetentionDays(BaseModel):
    """Days each kind of data is kept."""

    events: int = Field(ge=1)
    # Closed alerts and cases, by when they last changed; open ones are always kept.
    alerts: int = Field(ge=1)
    cases: int = Field(ge=1)
    # Response actions; those waiting for a decision are always kept.
    actions: int = Field(ge=1)
    # The email log.
    notifications: int = Field(ge=1)
    # Analysts' verdicts, kept to retrain the models.
    labels: int = Field(ge=1)


class RetentionRun(BaseModel):
    at: datetime
    deleted: Dict[str, int]


class Retention(BaseModel):
    days: RetentionDays
    defaults: RetentionDays
    max_days: int
    last_run: Optional[RetentionRun] = None


class RetentionUpdate(BaseModel):
    events: Optional[int] = Field(None, ge=1)
    alerts: Optional[int] = Field(None, ge=1)
    cases: Optional[int] = Field(None, ge=1)
    actions: Optional[int] = Field(None, ge=1)
    notifications: Optional[int] = Field(None, ge=1)
    labels: Optional[int] = Field(None, ge=1)
