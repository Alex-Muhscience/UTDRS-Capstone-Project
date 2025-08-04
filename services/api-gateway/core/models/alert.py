from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from bson import ObjectId
from core.models.user import PyObjectId

class AlertBase(BaseModel):
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    source: str  # IDS, Firewall, SIEM, etc.
    type: str  # malware, intrusion, anomaly, etc.
    status: str = "open"  # open, in_progress, resolved, closed, false_positive
    tags: List[str] = []
    asset_ids: List[str] = []
    event_ids: List[str] = []

class AlertCreate(AlertBase):
    created_by: Optional[str] = None
    
class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None
    event_ids: Optional[List[str]] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None

class AlertInDB(AlertBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
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
                "title": "Suspicious Login Activity",
                "description": "Multiple failed login attempts detected from unusual location",
                "severity": "high",
                "source": "SIEM",
                "type": "intrusion",
                "status": "open",
                "tags": ["login", "brute-force"],
                "asset_ids": ["60d5ec2dcb43a5e37d0c7514"],
                "event_ids": ["60d5ec2dcb43a5e37d0c7515", "60d5ec2dcb43a5e37d0c7516"],
                "created_at": "2023-04-01T10:00:00.000Z",
                "updated_at": "2023-04-01T10:00:00.000Z",
                "created_by": "60d5ec2dcb43a5e37d0c7517",
                "assigned_to": "60d5ec2dcb43a5e37d0c7518",
                "notes": "Investigating the source of these login attempts",
                "metadata": {"ip_address": "192.168.1.1", "country": "Unknown"}
            }
        }

class Alert(AlertBase):
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    metadata: Dict[str, Any] = {}
    
    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
                "title": "Suspicious Login Activity",
                "description": "Multiple failed login attempts detected from unusual location",
                "severity": "high",
                "source": "SIEM",
                "type": "intrusion",
                "status": "open",
                "tags": ["login", "brute-force"],
                "asset_ids": ["60d5ec2dcb43a5e37d0c7514"],
                "event_ids": ["60d5ec2dcb43a5e37d0c7515", "60d5ec2dcb43a5e37d0c7516"],
                "created_at": "2023-04-01T10:00:00.000Z",
                "updated_at": "2023-04-01T10:00:00.000Z",
                "created_by": "60d5ec2dcb43a5e37d0c7517",
                "assigned_to": "60d5ec2dcb43a5e37d0c7518",
                "notes": "Investigating the source of these login attempts",
                "metadata": {"ip_address": "192.168.1.1", "country": "Unknown"}
            }
        }