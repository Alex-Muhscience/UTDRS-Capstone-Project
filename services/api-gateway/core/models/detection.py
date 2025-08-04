from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from bson import ObjectId
from core.models.user import PyObjectId

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
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    notes: Optional[str] = None
    performance_metrics: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
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
                "performance_metrics": {"avg_execution_time": 0.23, "false_positive_rate": 0.05},
                "metadata": {"mitre_tactic": "TA0006", "mitre_technique": "T1110"}
            }
        }

class DetectionRule(DetectionRuleBase):
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    notes: Optional[str] = None
    performance_metrics: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    
    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
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
                "performance_metrics": {"avg_execution_time": 0.23, "false_positive_rate": 0.05},
                "metadata": {"mitre_tactic": "TA0006", "mitre_technique": "T1110"}
            }
        }