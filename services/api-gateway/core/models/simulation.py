from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from bson import ObjectId
from core.models.user import PyObjectId

class SimulationBase(BaseModel):
    name: str
    description: str
    scenario_type: str  # ransomware, data-exfiltration, lateral-movement, etc.
    status: str = "idle"  # idle, running, completed, failed
    target_assets: List[str] = []  # Asset IDs
    scope: str  # network, endpoint, user
    intensity: str = "low"  # low, medium, high
    scheduled_start: Optional[datetime] = None
    scheduled_end: Optional[datetime] = None

class SimulationCreate(SimulationBase):
    created_by: Optional[str] = None

class SimulationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scenario_type: Optional[str] = None
    status: Optional[str] = None
    target_assets: Optional[List[str]] = None
    scope: Optional[str] = None
    intensity: Optional[str] = None
    scheduled_start: Optional[datetime] = None
    scheduled_end: Optional[datetime] = None
    notes: Optional[str] = None

class SimulationInDB(SimulationBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    notes: Optional[str] = None
    results: Dict[str, Any] = Field(default_factory=dict)
    events_generated: List[str] = []  # Event IDs
    alerts_generated: List[str] = []  # Alert IDs
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
                "name": "Ransomware Simulation",
                "description": "Simulates a ransomware attack targeting file servers",
                "scenario_type": "ransomware",
                "status": "completed",
                "target_assets": ["60d5ec2dcb43a5e37d0c7514", "60d5ec2dcb43a5e37d0c7515"],
                "scope": "endpoint",
                "intensity": "medium",
                "scheduled_start": "2023-04-01T01:00:00.000Z",
                "scheduled_end": "2023-04-01T03:00:00.000Z",
                "created_at": "2023-03-25T00:00:00.000Z",
                "updated_at": "2023-04-01T03:15:00.000Z",
                "created_by": "60d5ec2dcb43a5e37d0c7517",
                "updated_by": "60d5ec2dcb43a5e37d0c7517",
                "actual_start": "2023-04-01T01:00:05.000Z",
                "actual_end": "2023-04-01T02:45:30.000Z",
                "notes": "Simulation ran successfully, all phases completed",
                "results": {
                    "detection_rate": 0.85,
                    "avg_detection_time": 6.5,
                    "false_positives": 2,
                    "true_positives": 12
                },
                "events_generated": ["60d5ec2dcb43a5e37d0c7520", "60d5ec2dcb43a5e37d0c7521"],
                "alerts_generated": ["60d5ec2dcb43a5e37d0c7522"],
                "metadata": {"attack_phases": 4, "ioc_generated": True}
            }
        }

class Simulation(SimulationBase):
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    notes: Optional[str] = None
    results: Dict[str, Any] = {}
    events_generated: List[str] = []
    alerts_generated: List[str] = []
    metadata: Dict[str, Any] = {}
    
    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
                "name": "Ransomware Simulation",
                "description": "Simulates a ransomware attack targeting file servers",
                "scenario_type": "ransomware",
                "status": "completed",
                "target_assets": ["60d5ec2dcb43a5e37d0c7514", "60d5ec2dcb43a5e37d0c7515"],
                "scope": "endpoint",
                "intensity": "medium",
                "scheduled_start": "2023-04-01T01:00:00.000Z",
                "scheduled_end": "2023-04-01T03:00:00.000Z",
                "created_at": "2023-03-25T00:00:00.000Z",
                "updated_at": "2023-04-01T03:15:00.000Z",
                "created_by": "60d5ec2dcb43a5e37d0c7517",
                "updated_by": "60d5ec2dcb43a5e37d0c7517",
                "actual_start": "2023-04-01T01:00:05.000Z",
                "actual_end": "2023-04-01T02:45:30.000Z",
                "notes": "Simulation ran successfully, all phases completed",
                "results": {
                    "detection_rate": 0.85,
                    "avg_detection_time": 6.5,
                    "false_positives": 2,
                    "true_positives": 12
                },
                "events_generated": ["60d5ec2dcb43a5e37d0c7520", "60d5ec2dcb43a5e37d0c7521"],
                "alerts_generated": ["60d5ec2dcb43a5e37d0c7522"],
                "metadata": {"attack_phases": 4, "ioc_generated": True}
            }
        }