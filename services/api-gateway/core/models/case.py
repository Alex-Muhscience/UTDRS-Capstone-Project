from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import AliasChoices, BaseModel, Field

from core.models.common import IdString

CaseStatus = Literal["open", "investigating", "contained", "resolved", "false_positive", "closed"]
Priority = Literal["critical", "high", "medium", "low", "info"]


class Entity(BaseModel):
    # user, asset, host, ip, sender, file_hash, domain
    type: str
    value: str
    # For an asset, its name (value is its id).
    name: Optional[str] = None


class TimelineEntry(BaseModel):
    at: datetime
    # created, alert_added, status_changed, owner_changed, priority_changed, note, title_changed
    kind: str
    actor: Optional[Dict[str, Any]] = None
    text: Optional[str] = None
    data: Dict[str, Any] = {}


class Explanation(BaseModel):
    """The case in plain language, for whoever has to act on it."""

    what_happened: str
    why_it_matters: str
    next_steps: List[str]


class Case(BaseModel):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    title: str
    status: CaseStatus
    priority: Priority
    owner_id: Optional[str] = None
    alert_ids: List[str]
    entities: List[Entity]
    techniques: List[str] = []
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    # When the case should be contained by, from its priority.
    due_at: datetime
    breached: bool = False
    timeline: List[TimelineEntry] = []
    explanation: Optional[Explanation] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    status: Optional[CaseStatus] = None
    priority: Optional[Priority] = None
    # A colleague's user id, or null to unassign.
    owner_id: Optional[str] = None


class CaseNote(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class CaseEvidence(BaseModel):
    alerts: List[Dict[str, Any]]
    events: List[Dict[str, Any]]
    entities: List[Entity]
