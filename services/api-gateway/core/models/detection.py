from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, computed_field

from core.services.rule_compiler import engine_status

from utils.time import utcnow
from core.models.common import IdString, PyObjectId


class DetectionRuleBase(BaseModel):
    name: str
    description: str
    rule_type: str  # signature, anomaly, behavior, correlation
    detection_source: str  # network, endpoint, log, etc.
    severity: str  # critical, high, medium, low, info
    status: str = "enabled"  # enabled, disabled, testing
    tags: List[str] = []
    logic: str  # The actual rule logic/query


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
    last_updated: datetime
