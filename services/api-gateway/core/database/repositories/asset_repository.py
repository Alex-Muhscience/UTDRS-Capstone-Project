from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pymongo import ReturnDocument
from core.database.repositories.base_repository import BaseRepository
from core.models.asset import AssetCreate, AssetUpdate

class AssetRepository(BaseRepository):
    def __init__(self):
        super().__init__("assets")
    
    async def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"name": name})
    
    async def find_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"ip_address": ip_address})
    
    async def find_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"mac_address": mac_address})
    
    async def find_by_type(self, asset_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"asset_type": asset_type}, limit=limit, skip=skip)
    
    async def find_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"status": status}, limit=limit, skip=skip)
    
    async def find_by_criticality(self, criticality: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"criticality": criticality}, limit=limit, skip=skip)
    
    async def find_by_department(self, department: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"department": department}, limit=limit, skip=skip)
    
    async def create_asset(self, asset: AssetCreate) -> str:
        asset_dict = asset.dict()
        
        asset_doc = {
            **asset_dict,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "vulnerabilities": [],
            "tags": [],
            "metadata": {}
        }
        
        return await self.insert_one(asset_doc)
    
    async def update_asset(self, id: str, asset_update: AssetUpdate) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
            
        update_data = asset_update.dict(exclude_unset=True)
        if update_data:
            update_data["updated_at"] = datetime.utcnow()
            
            result = await self.collection.find_one_and_update(
                {"_id": ObjectId(id)},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )
            return result
        return await self.find_by_id(id)
    
    async def update_last_seen(self, id: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "last_seen": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    async def add_vulnerability(self, id: str, vulnerability: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$addToSet": {"vulnerabilities": vulnerability},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    async def remove_vulnerability(self, id: str, vulnerability: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$pull": {"vulnerabilities": vulnerability},
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
    
    async def search_assets(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search assets by keyword in name, description, or notes."""
        search_query = {
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"notes": {"$regex": query, "$options": "i"}}
            ]
        }
        return await self.find_many(search_query, limit=limit, skip=skip)