from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from bson import ObjectId
from core.models.user import PyObjectId

class EventBase(BaseModel):
    timestamp: datetime
    event_type: str  # authentication, network, file, process, etc.
    source: str  # source system or device
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    action: Optional[str] = None  # allow, block, detect, etc.
    user_id: Optional[str] = None
    asset_id: Optional[str] = None
    description: str
    raw_data: Dict[str, Any] = {}

class EventCreate(EventBase):
    pass

class EventUpdate(BaseModel):
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    severity: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class EventInDB(EventBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = []
    severity: Optional[str] = None  # critical, high, medium, low, info
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
                "timestamp": "2023-04-01T10:00:00.000Z",
                "event_type": "authentication",
                "source": "Windows Active Directory",
                "source_ip": "192.168.1.5",
                "destination_ip": "192.168.1.100",
                "protocol": "TCP",
                "action": "failure",
                "user_id": "60d5ec2dcb43a5e37d0c7517",
                "asset_id": "60d5ec2dcb43a5e37d0c7518",
                "description": "Failed login attempt",
                "raw_data": {"event_id": 4625, "workstation_name": "WS001"},
                "created_at": "2023-04-01T10:00:01.000Z",
                "updated_at": "2023-04-01T10:00:01.000Z",
                "tags": ["authentication", "failure"],
                "severity": "medium",
                "metadata": {"location": "HQ", "department": "IT"}
            }
        }

class Event(EventBase):
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    tags: List[str] = []
    severity: Optional[str] = None
    metadata: Dict[str, Any] = {}
    
    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
                "timestamp": "2023-04-01T10:00:00.000Z",
                "event_type": "authentication",
                "source": "Windows Active Directory",
                "source_ip": "192.168.1.5",
                "destination_ip": "192.168.1.100",
                "protocol": "TCP",
                "action": "failure",
                "user_id": "60d5ec2dcb43a5e37d0c7517",
                "asset_id": "60d5ec2dcb43a5e37d0c7518",
                "description": "Failed login attempt",
                "raw_data": {"event_id": 4625, "workstation_name": "WS001"},
                "created_at": "2023-04-01T10:00:01.000Z",
                "updated_at": "2023-04-01T10:00:01.000Z",
                "tags": ["authentication", "failure"],
                "severity": "medium",
                "metadata": {"location": "HQ", "department": "IT"}
            }
        }