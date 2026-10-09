from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime

class AlertBase(BaseModel):
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    source: str
    event_ids: List[str] = []
    detection_type: str  # signature, anomaly, ml
    details: Dict[str, Any] = {}
    status: str = "open"  # open, in_progress, resolved, closed, false_positive

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    
    class Config:
        allow_population_by_field_name = True
