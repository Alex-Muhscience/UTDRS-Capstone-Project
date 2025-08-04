from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pymongo import ReturnDocument
from core.database.repositories.base_repository import BaseRepository
from core.models.user import UserInDB, UserCreate, UserUpdate
from utils.security import get_password_hash

class UserRepository(BaseRepository):
    def __init__(self):
        super().__init__("users")
    
    async def find_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"username": username})
    
    async def find_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"email": email})
    
    async def create_user(self, user: UserCreate) -> str:
        user_dict = user.dict()
        password = user_dict.pop("password")
        
        # Create user document
        user_doc = {
            "username": user_dict["username"],
            "email": user_dict["email"],
            "firstName": user_dict.get("firstName"),
            "lastName": user_dict.get("lastName"),
            "role": user_dict.get("role", "analyst"),
            "active": user_dict.get("active", True),
            "passwordHash": get_password_hash(password),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow(),
            "preferences": {}
        }
        
        return await self.insert_one(user_doc)
    
    async def update_user(self, id: str, user_update: UserUpdate) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
            
        update_data = user_update.dict(exclude_unset=True)
        if update_data:
            update_data["updatedAt"] = datetime.utcnow()
            
            result = await self.collection.find_one_and_update(
                {"_id": ObjectId(id)},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )
            return result
        return await self.find_by_id(id)
    
    async def update_last_login(self, id: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"lastLogin": datetime.utcnow(), "updatedAt": datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    async def change_password(self, id: str, new_password: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "passwordHash": get_password_hash(new_password),
                    "updatedAt": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
