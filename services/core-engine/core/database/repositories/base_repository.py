from typing import List, Dict, Any, Optional, TypeVar, Generic
from bson import ObjectId
from pydantic import BaseModel
from core.database.connection import db

T = TypeVar('T', bound=BaseModel)

class BaseRepository:
    def __init__(self, collection_name: str):
        # Instead of calling get_database() which is now async, use db.client directly
        if db.client is None:
            raise ConnectionError("Database connection not established")
        self.db = db.client[db.db_name]
        self.collection = self.db[collection_name]
    
    async def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        result = await self.collection.find_one(query)
        if result:
            result["_id"] = str(result["_id"])
        return result
    
    async def find_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
        return await self.find_one({"_id": ObjectId(id)})
    
    async def find_many(self, query: Dict[str, Any], limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        cursor = self.collection.find(query).skip(skip).limit(limit)
        results = await cursor.to_list(length=limit)
        for result in results:
            result["_id"] = str(result["_id"])
        return results
    
    async def count(self, query: Dict[str, Any]) -> int:
        return await self.collection.count_documents(query)
    
    async def insert_one(self, document: Dict[str, Any]) -> str:
        result = await self.collection.insert_one(document)
        return str(result.inserted_id)
    
    async def insert_many(self, documents: List[Dict[str, Any]]) -> List[str]:
        result = await self.collection.insert_many(documents)
        return [str(id) for id in result.inserted_ids]
    
    async def update_one(self, id: str, update_data: Dict[str, Any]) -> bool:
        if not ObjectId.is_valid(id):
            return False
        result = await self.collection.update_one(
            {"_id": ObjectId(id)}, {"$set": update_data}
        )
        return result.modified_count > 0
    
    async def delete_one(self, id: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
        result = await self.collection.delete_one({"_id": ObjectId(id)})
        return result.deleted_count > 0