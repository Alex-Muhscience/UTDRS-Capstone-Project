from typing import Any, Dict, List, Optional, Type, TypeVar

from bson import ObjectId
from pydantic import BaseModel
from pymongo import DESCENDING

from core.database.connection import get_database
from core.tenancy import scoped

T = TypeVar("T", bound=BaseModel)


class BaseRepository:
    def __init__(self, collection_name: str):
        self.db = get_database()
        # Scoped to the current tenant for collections that hold an organisation's data.
        self.collection = scoped(self.db, collection_name)

    async def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(query)

    async def find_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
        return await self.find_one({"_id": ObjectId(id)})

    async def find_many(
        self, query: Dict[str, Any], limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        # Newest first: ObjectIds start with their creation time.
        cursor = self.collection.find(query).sort("_id", DESCENDING).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)

    async def count_by(
        self, field: str, query: Optional[Dict[str, Any]] = None
    ) -> Dict[str, int]:
        """Number of documents for each value of a field."""
        pipeline = [{"$match": query or {}}, {"$group": {"_id": f"${field}", "count": {"$sum": 1}}}]
        cursor = await self.collection.aggregate(pipeline)
        return {doc["_id"]: doc["count"] async for doc in cursor if doc["_id"] is not None}

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
