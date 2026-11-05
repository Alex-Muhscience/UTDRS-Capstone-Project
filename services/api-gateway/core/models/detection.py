from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from bson import ObjectId
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, computed_field

from core.services.rule_compiler import engine_status

from utils.time import utcnow
from core.models.common import IdString, PyObjectId


class RuleTestCase(BaseModel):
    """An example event the rule must match, or must not."""

    name: str = Field(min_length=1, max_length=200)
    # As sent to POST /events/: event_type, source, and the rest (raw_data, or fields given directly).
    event: Dict[str, Any]
    expect: Literal["match", "no_match"] = "match"


class RuleTestResult(BaseModel):
    name: Optional[str] = None
    expect: str
    matched: bool
    passed: bool


class RuleTestRun(BaseModel):
    # False when the engine cannot run the logic: then nothing was tested, and `reason` says why.
    ran: bool
    reason: Optional[str] = None
    passed: bool
    results: List[RuleTestResult] = []


class RuleTestRequest(BaseModel):
    """Test logic before saving it."""

    logic: str = Field(min_length=1, max_length=5000)
    test_cases: List[RuleTestCase] = Field(default=[], max_length=50)


class RuleVersion(BaseModel):
    version: int
    # created, updated, status, tags, restored from N
    change: str
    changed_by: Optional[str] = None
    at: datetime
    rule: Dict[str, Any]


class DetectionRuleBase(BaseModel):
    name: str
    description: str
    rule_type: str  # signature, anomaly, behavior, correlation
    detection_source: str  # network, endpoint, log, etc.
    severity: str  # critical, high, medium, low, info
    status: str = "enabled"  # enabled, disabled, testing
    tags: List[str] = []
    logic: str  # The actual rule logic/query
    # Example events the rule must match, or must not; checked when the rule is saved.
    test_cases: List[RuleTestCase] = []


class DetectionRuleCreate(DetectionRuleBase):
    created_by: Optional[str] = None


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[str] = None
    detection_source: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    logic: Optional[str] = None
    notes: Optional[str] = None
    test_cases: Optional[List[RuleTestCase]] = None


class DetectionRuleInDB(DetectionRuleBase):
    id: PyObjectId = Field(default_factory=ObjectId, alias="_id")
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    notes: Optional[str] = None
    performance_metrics: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "60d5ec2dcb43a5e37d0c7513",
                "name": "Multiple Failed Logins",
                "description": "Detects multiple failed login attempts from the same source IP",
                "rule_type": "correlation",
                "detection_source": "authentication logs",
                "severity": "medium",
                "status": "enabled",
                "tags": ["authentication", "brute-force"],
                "logic": "SELECT source_ip, COUNT(*) as count FROM auth_events WHERE status = 'failure' AND timestamp > NOW() - INTERVAL 5 MINUTE GROUP BY source_ip HAVING count >= 5",
                "created_at": "2023-01-01T00:00:00.000Z",
                "updated_at": "2023-04-01T10:00:00.000Z",
                "created_by": "60d5ec2dcb43a5e37d0c7517",
                "updated_by": "60d5ec2dcb43a5e37d0c7518",
                "notes": "Adjusted threshold from 10 to 5 due to increased attack frequency",
                "performance_metrics": {
                    "avg_execution_time": 0.23,
                    "false_positive_rate": 0.05,
                },
                "metadata": {"mitre_tactic": "TA0006", "mitre_technique": "T1110"},
            }
        },
    )


class RuleEngineStatus(BaseModel):
    # Whether the core engine can run this rule's logic. It does so while the rule is enabled.
    runs: bool
    # Why not, when it cannot.
    reason: Optional[str] = None


class DetectionRule(DetectionRuleBase):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))

    @computed_field
    @property
    def engine(self) -> RuleEngineStatus:
        runs, reason = engine_status(self.logic)
        return RuleEngineStatus(runs=runs, reason=reason)

    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    notes: Optional[str] = None
    performance_metrics: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    # Changes so far (rule_versions); 0 for a rule from before versions.
    version: int = 0

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "id": "60d5ec2dcb43a5e37d0c7513",
                "name": "Multiple Failed Logins",
                "description": "Detects multiple failed login attempts from the same source IP",
                "rule_type": "correlation",
                "detection_source": "authentication logs",
                "severity": "medium",
                "status": "enabled",
                "tags": ["authentication", "brute-force"],
                "logic": "SELECT source_ip, COUNT(*) as count FROM auth_events WHERE status = 'failure' AND timestamp > NOW() - INTERVAL 5 MINUTE GROUP BY source_ip HAVING count >= 5",
                "created_at": "2023-01-01T00:00:00.000Z",
                "updated_at": "2023-04-01T10:00:00.000Z",
                "created_by": "60d5ec2dcb43a5e37d0c7517",
                "updated_by": "60d5ec2dcb43a5e37d0c7518",
                "notes": "Adjusted threshold from 10 to 5 due to increased attack frequency",
                "performance_metrics": {
                    "avg_execution_time": 0.23,
                    "false_positive_rate": 0.05,
                },
                "metadata": {"mitre_tactic": "TA0006", "mitre_technique": "T1110"},
            }
        },
    )


class CoreEngineStatus(BaseModel):
    configured: bool
    reachable: bool


class RuleSyncStatus(BaseModel):
    attempted_at: datetime
    ok: bool
    error: Optional[str] = None
    # The enabled rules the engine can run, as sent in the last attempt.
    rules_sent: int
    succeeded_at: Optional[datetime] = None


class AnalysisQueueStatus(BaseModel):
    # Events stored but not yet analysed (the engine is busy or unreachable), and since when.
    waiting: int
    oldest_waiting_since: Optional[datetime] = None
    # Events the engine could not analyse within ANALYSIS_GIVE_UP_HOURS, or rejected; replayable.
    failed_last_day: int


class DetectionStatus(BaseModel):
    # standalone: no core engine configured; active: engine reachable; degraded: configured but unreachable
    status: str
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    testing_rules: int
    core_engine: CoreEngineStatus
    # The last time the rules were sent to the core engine; null without an engine.
    rule_sync: Optional[RuleSyncStatus] = None
    # Events waiting for, or failed in, analysis; null without an engine.
    analysis: Optional[AnalysisQueueStatus] = None
    last_updated: datetime
