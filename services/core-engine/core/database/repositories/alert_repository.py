from typing import List, Dict, Any, Optional
from datetime import datetime
from core.database.repositories.base_repository import BaseRepository
from core.models.schema.alert import AlertCreate, Alert

class AlertRepository(BaseRepository):
    def __init__(self):
        super().__init__("alerts")
    
    async def create_alert(self, alert_data):
        alert_dict = alert_data.model_dump()
        
        # Add timestamps
        now = datetime.utcnow()
        alert_dict["created_at"] = now
        alert_dict["updated_at"] = now
        
        # Insert into database
        alert_id = await self.insert_one(alert_dict)
        
        # Get the created alert
        alert_doc = await self.find_by_id(alert_id)
        return Alert(**alert_doc)
    
    async def update_alert_status(self, alert_id, status, assigned_to=None):
        update_data = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if assigned_to:
            update_data["assigned_to"] = assigned_to
            
        success = await self.update_one(alert_id, update_data)
        if success:
            alert_doc = await self.find_by_id(alert_id)
            return Alert(**alert_doc)
        return None
