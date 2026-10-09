from pydantic import AliasChoices, BaseModel, BeforeValidator, ConfigDict, Field
from typing import Annotated
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

# Accepts the ObjectId read from MongoDB, exposes a string.
IdString = Annotated[str, BeforeValidator(lambda v: str(v) if not isinstance(v, str) else v)]


class Alert(AlertBase):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    
    model_config = ConfigDict(populate_by_name=True)
