from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pymongo import ReturnDocument
from core.database.repositories.base_repository import BaseRepository
from core.models.detection import DetectionRuleCreate, DetectionRuleUpdate

class DetectionRepository(BaseRepository):
    def __init__(self):
        super().__init__("detection_rules")
    
    async def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"name": name})
    
    async def find_by_type(self, rule_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"rule_type": rule_type}, limit=limit, skip=skip)
    
    async def find_by_source(self, detection_source: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"detection_source": detection_source}, limit=limit, skip=skip)
    
    async def find_by_severity(self, severity: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"severity": severity}, limit=limit, skip=skip)
    
    async def find_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"status": status}, limit=limit, skip=skip)
    
    async def find_by_tag(self, tag: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"tags": tag}, limit=limit, skip=skip)
    
    async def create_rule(self, rule: DetectionRuleCreate, user_id: Optional[str] = None) -> str:
        rule_dict = rule.dict()
        
        if user_id:
            rule_dict["created_by"] = user_id
            rule_dict["updated_by"] = user_id
        
        rule_doc = {
            **rule_dict,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "performance_metrics": {},
            "metadata": {}
        }
        
        return await self.insert_one(rule_doc)
    
    async def update_rule(self, id: str, rule_update: DetectionRuleUpdate, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
            
        update_data = rule_update.dict(exclude_unset=True)
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            
            if user_id:
                update_data["updated_by"] = user_id
            
            result = await self.collection.find_one_and_update(
                {"_id": ObjectId(id)},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )
            return result
        return await self.find_by_id(id)
    
    async def update_status(self, id: str, status: str, user_id: Optional[str] = None) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        update_doc = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if user_id:
            update_doc["updated_by"] = user_id
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_doc}
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
    
    async def update_performance_metrics(self, id: str, metrics: Dict[str, Any]) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "performance_metrics": metrics,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    async def search_rules(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search rules by keyword in name, description, or logic."""
        search_query = {
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}},
                {"logic": {"$regex": query, "$options": "i"}}
            ]
        }
        return await self.find_many(search_query, limit=limit, skip=skip)