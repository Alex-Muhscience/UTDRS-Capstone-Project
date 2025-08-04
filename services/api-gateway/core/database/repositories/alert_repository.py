from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pymongo import ReturnDocument
from core.database.repositories.base_repository import BaseRepository
from core.models.alert import AlertCreate, AlertUpdate

class AlertRepository(BaseRepository):
    def __init__(self):
        super().__init__("alerts")
    
    async def find_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"status": status}, limit=limit, skip=skip)
    
    async def find_by_severity(self, severity: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"severity": severity}, limit=limit, skip=skip)
    
    async def find_by_assigned_to(self, user_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        if not ObjectId.is_valid(user_id):
            return []
        return await self.find_many({"assigned_to": user_id}, limit=limit, skip=skip)
    
    async def create_alert(self, alert: AlertCreate, user_id: Optional[str] = None) -> str:
        alert_dict = alert.dict()
        
        if user_id:
            alert_dict["created_by"] = user_id
        
        alert_doc = {
            **alert_dict,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "metadata": {}
        }
        
        return await self.insert_one(alert_doc)
    
    async def update_alert(self, id: str, alert_update: AlertUpdate, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
            
        update_data = alert_update.dict(exclude_unset=True)
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            
            result = await self.collection.find_one_and_update(
                {"_id": ObjectId(id)},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )
            return result
        return await self.find_by_id(id)
    
    async def assign_alert(self, id: str, assigned_to: str) -> bool:
        if not ObjectId.is_valid(id) or not ObjectId.is_valid(assigned_to):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "assigned_to": assigned_to,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    async def update_status(self, id: str, status: str, notes: Optional[str] = None) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        update_doc = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if notes:
            update_doc["notes"] = notes
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_doc}
        )
        return result.modified_count > 0
    
    async def add_event_to_alert(self, alert_id: str, event_id: str) -> bool:
        if not ObjectId.is_valid(alert_id) or not ObjectId.is_valid(event_id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(alert_id)},
            {
                "$addToSet": {"event_ids": event_id},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    async def add_tag(self, id: str, tag: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$addToSet": {"tags": tag},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    async def remove_tag(self, id: str, tag: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$pull": {"tags": tag},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    async def search_alerts(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search alerts by keyword in title or description."""
        search_query = {
            "$or": [
                {"title": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}}
            ]
        }
        return await self.find_many(search_query, limit=limit, skip=skip)