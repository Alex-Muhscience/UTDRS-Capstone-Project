from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from core.models.case import Priority
from core.models.common import IdString

Mode = Literal["automatic", "approval", "notify"]
ActionStatus = Literal["pending", "running", "succeeded", "failed", "rejected", "undoing", "undone"]

# Parameters a playbook fills in from the case, so its steps need not give them.
FROM_CASE = {"m365.purge_message": {"recipients"}}


class Target(BaseModel):
    # user, message, case
    type: str = Field(min_length=1, max_length=40)
    value: str = Field(min_length=1, max_length=500)


class ActionType(BaseModel):
    name: str
    label: str
    description: str
    connector: str
    connector_name: str
    target: str
    params: List[str]
    can_undo: bool
    disruptive: bool
    connected: bool


class ActionRequest(BaseModel):
    action: str
    target: Target
    params: Dict[str, Any] = {}
    case_id: Optional[str] = None


class ActionDecision(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


class Action(BaseModel):
    id: IdString
    action: str
    label: str
    target: Target
    params: Dict[str, Any] = {}
    status: ActionStatus
    # How it was decided: automatic (it ran without waiting), approval or notify.
    mode: Mode
    reason: Optional[str] = None
    protected: bool = False
    case_id: Optional[str] = None
    alert_id: Optional[str] = None
    playbook: Optional[Dict[str, Any]] = None
    requested_by: Dict[str, Any]
    decided_by: Optional[Dict[str, Any]] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    can_undo: bool = False
    undoes: Optional[str] = None
    undone_by: Optional[str] = None


class ResponseSettings(BaseModel):
    """How far playbooks may act on their own in this organisation."""

    mode: Mode
    max_actions_per_hour: int = Field(ge=0, le=1000)
    # Accounts never disrupted automatically, by email address or user name.
    protected_accounts: List[str] = Field(max_length=500)


class ResponseSettingsUpdate(BaseModel):
    mode: Optional[Mode] = None
    max_actions_per_hour: Optional[int] = Field(None, ge=0, le=1000)
    protected_accounts: Optional[List[str]] = Field(None, max_length=500)


class PlaybookTrigger(BaseModel):
    """Which alerts start the playbook: at least this severe, with any of these tags or techniques (or any, when neither is given)."""

    min_severity: Priority = "medium"
    tags: List[str] = Field([], max_length=50)
    techniques: List[str] = Field([], max_length=50)


class PlaybookStep(BaseModel):
    action: str
    # The case's entities it acts on: every user, every message, or the case itself.
    target: str
    params: Dict[str, Any] = {}

    @model_validator(mode="after")
    def known_action(self):
        from core.services.response_actions import CATALOGUE, UNDO_ONLY

        kind = CATALOGUE.get(self.action)
        if not kind or self.action in UNDO_ONLY:
            raise ValueError(f"There is no action called {self.action}")
        if self.target != kind.target:
            raise ValueError(f"{kind.label} acts on a {kind.target}, not a {self.target}")
        missing = [p for p in kind.params if p not in self.params and p not in FROM_CASE.get(self.action, set())]
        if missing:
            raise ValueError(f"{kind.label} needs {', '.join(missing)}")
        return self


class PlaybookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field("", max_length=1000)
    enabled: bool = True
    mode: Mode = "approval"
    trigger: PlaybookTrigger = PlaybookTrigger()
    steps: List[PlaybookStep] = Field(min_length=1, max_length=10)

    @field_validator("name")
    @classmethod
    def strip(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("A playbook needs a name")
        return value.strip()


class PlaybookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    enabled: Optional[bool] = None
    mode: Optional[Mode] = None
    trigger: Optional[PlaybookTrigger] = None
    steps: Optional[List[PlaybookStep]] = Field(None, min_length=1, max_length=10)


class Playbook(PlaybookCreate):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    # Set for the playbooks UTDRS provides; they can be changed and turned off, not deleted.
    built_in: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    last_run_at: Optional[datetime] = None


class PlaybookRun(BaseModel):
    case_id: str


class PlaybookRunResult(BaseModel):
    actions: List[Action]
    skipped: List[str]
