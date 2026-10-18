from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, Field

from core.models.common import IdString


class Figure(BaseModel):
    value: Optional[float] = None
    previous: Optional[float] = None


class Week(BaseModel):
    start: datetime
    end: datetime
    count: int


class Threat(BaseModel):
    name: str
    count: int


class Target(BaseModel):
    type: str  # user or device
    name: str
    cases: int


class ActionCount(BaseModel):
    label: str
    count: int


class ActionSummary(BaseModel):
    taken: int
    automatic: int
    approved: int
    undone: int
    failed: int
    rejected: int
    by_action: List[ActionCount]


class OpenCase(BaseModel):
    id: str
    title: str
    priority: str
    due_at: datetime
    overdue: bool


class Outstanding(BaseModel):
    open_cases: int
    overdue: int
    by_priority: Dict[str, int]
    top: List[OpenCase]
    awaiting_approval: int


class ReportData(BaseModel):
    period: str
    title: str
    organisation: str
    start: datetime
    end: datetime
    headline: List[str]
    # alerts, cases_opened, cases_closed, critical_cases, actions_taken,
    # median_hours_to_resolve, within_deadline_percent: this month and the month before
    figures: Dict[str, Figure]
    alerts_by_severity: Dict[str, int]
    weekly_alerts: List[Week]
    top_threats: List[Threat]
    most_targeted: List[Target]
    actions: ActionSummary
    outstanding: Outstanding
    recommendations: List[str]


class Report(BaseModel):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    period: str
    generated_at: datetime
    generated_by: Dict[str, Any]
    data: ReportData


class ReportSummary(BaseModel):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    period: str
    title: str
    headline: List[str]
    generated_at: datetime


class ReportRequest(BaseModel):
    # The month, as YYYY-MM; by default the last full month.
    period: Optional[str] = Field(None, pattern=r"^\d{4}-(0[1-9]|1[0-2])$")
