from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pymongo import ReturnDocument, DESCENDING
from core.database.repositories.base_repository import BaseRepository
from core.models.event import EventCreate, EventUpdate

class EventRepository(BaseRepository):
    def __init__(self):
        super().__init__("events")
    
    async def find_by_type(self, event_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"event_type": event_type}, limit=limit, skip=skip)
    
    async def find_by_asset_id(self, asset_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        if not ObjectId.is_valid(asset_id):
            return []
        return await self.find_many({"asset_id": asset_id}, limit=limit, skip=skip)
    
    async def find_by_user_id(self, user_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        if not ObjectId.is_valid(user_id):
            return []
        return await self.find_many({"user_id": user_id}, limit=limit, skip=skip)
    
    async def find_by_ip(self, ip_address: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        query = {
            "$or": [
                {"source_ip": ip_address},
                {"destination_ip": ip_address}
            ]
        }
        return await self.find_many(query, limit=limit, skip=skip)
    
    async def find_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self.collection.find().sort("timestamp", DESCENDING).limit(limit)
        return await cursor.to_list(length=limit)
    
    async def create_event(self, event: EventCreate) -> str:
        event_dict = event.dict()
        
        event_doc = {
            **event_dict,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "tags": [],
            "metadata": {}
        }
        
        return await self.insert_one(event_doc)
    
    async def update_event(self, id: str, event_update: EventUpdate) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
            
        update_data = event_update.dict(exclude_unset=True)
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            
            result = await self.collection.find_one_and_update(
                {"_id": ObjectId(id)},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )
            return result
        return await self.find_by_id(id)
    
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
    
    async def set_severity(self, id: str, severity: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "severity": severity,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    async def search_events(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search events by keyword in description."""
        search_query = {"description": {"$regex": query, "$options": "i"}}
        return await self.find_many(search_query, limit=limit, skip=skip)
    
    async def find_by_time_range(self, start_time: datetime, end_time: datetime, 
                                limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Find events within a specific time range."""
        query = {
            "timestamp": {
                "$gte": start_time,
                "$lte": end_time
            }
        }
        return await self.find_many(query, limit=limit, skip=skip)