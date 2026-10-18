from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import AliasChoices, BaseModel, Field, model_validator

from core.models.alert import Alert
from core.models.case import Priority
from core.models.common import IdString

Verdict = Literal["true_positive", "false_positive", "benign"]
EntityType = Literal["user", "host", "asset", "ip", "sender", "file_hash", "message"]


class VerdictRequest(BaseModel):
    verdict: Verdict
    note: Optional[str] = Field(None, max_length=1000)


class SuppressionEntity(BaseModel):
    type: EntityType
    value: str = Field(min_length=1, max_length=500)


class SuppressionCreate(BaseModel):
    """
    Alerts matching every condition given (at least one) and no more severe than
    `max_severity` are suppressed. With only an entity, it is an allow-list entry.
    """

    name: str = Field(min_length=1, max_length=100)
    # Why: shown to everyone who wonders where the alerts went.
    reason: str = Field(min_length=1, max_length=500)
    title_contains: Optional[str] = Field(None, max_length=200)
    # A detector, as the quality report names it (rule:<id>, or <kind>:<title>).
    detector: Optional[str] = Field(None, max_length=300)
    entity: Optional[SuppressionEntity] = None
    max_severity: Priority = "high"
    # Days until it stops applying; none means never (administrators only).
    expires_in_days: Optional[int] = Field(90, ge=1, le=365)

    @model_validator(mode="after")
    def says_what(self):
        if not ((self.title_contains or "").strip() or self.detector or self.entity):
            raise ValueError("Say which alerts to suppress: a title, a detector or an entity")
        return self


class SuppressionUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    reason: Optional[str] = Field(None, min_length=1, max_length=500)
    enabled: Optional[bool] = None
    max_severity: Optional[Priority] = None
    expires_in_days: Optional[int] = Field(None, ge=0, le=365, description="0 for never")


class Suppression(BaseModel):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    name: str
    reason: str
    title_contains: Optional[str] = None
    detector: Optional[str] = None
    entity: Optional[SuppressionEntity] = None
    max_severity: Priority
    enabled: bool
    expires_at: Optional[datetime] = None
    hits: int
    last_hit_at: Optional[datetime] = None
    created_by: Dict[str, Any]
    created_at: datetime


class SuppressionSuggestion(BaseModel):
    name: str
    detector: str
    entity: Optional[SuppressionEntity] = None
    max_severity: Priority


class VerdictResult(BaseModel):
    alert: Alert
    # For a false positive or benign verdict: a suppression for alerts like this one, to
    # review and create (POST /tuning/suppressions); nothing is suppressed by itself.
    suggestion: Optional[SuppressionSuggestion] = None


class DetectorQuality(BaseModel):
    detector: str
    name: str
    alerts: int
    suppressed: int
    true_positive: int
    false_positive: int
    benign: int
    # Real threats among the alerts given a verdict; none before any verdict.
    precision: Optional[float] = None
    # Most of at least five verdicts were not real threats.
    noisy: bool
