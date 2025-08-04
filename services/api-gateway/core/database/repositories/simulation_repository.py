from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pymongo import ReturnDocument
from core.database.repositories.base_repository import BaseRepository
from core.models.simulation import SimulationCreate, SimulationUpdate

class SimulationRepository(BaseRepository):
    def __init__(self):
        super().__init__("simulations")
    
    async def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return await self.find_one({"name": name})
    
    async def find_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"status": status}, limit=limit, skip=skip)
    
    async def find_by_scenario_type(self, scenario_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"scenario_type": scenario_type}, limit=limit, skip=skip)
    
    async def find_by_target_asset(self, asset_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        if not ObjectId.is_valid(asset_id):
            return []
        return await self.find_many({"target_assets": asset_id}, limit=limit, skip=skip)
    
    async def find_scheduled(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        query = {
            "status": "idle",
            "scheduled_start": {"$gte": now}
        }
        return await self.find_many(query, limit=limit, skip=skip)
    
    async def find_running(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        return await self.find_many({"status": "running"}, limit=limit, skip=skip)
    
    async def create_simulation(self, simulation: SimulationCreate, user_id: Optional[str] = None) -> str:
        simulation_dict = simulation.dict()
        
        if user_id:
            simulation_dict["created_by"] = user_id
            simulation_dict["updated_by"] = user_id
        
        simulation_doc = {
            **simulation_dict,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "results": {},
            "events_generated": [],
            "alerts_generated": [],
            "metadata": {}
        }
        
        return await self.insert_one(simulation_doc)
    
    async def update_simulation(self, id: str, simulation_update: SimulationUpdate, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
            
        update_data = simulation_update.dict(exclude_unset=True)
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
            
        if status == "running":
            update_doc["actual_start"] = datetime.utcnow()
        elif status in ["completed", "failed"]:
            update_doc["actual_end"] = datetime.utcnow()
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_doc}
        )
        return result.modified_count > 0
    
    async def add_event_to_simulation(self, simulation_id: str, event_id: str) -> bool:
        if not ObjectId.is_valid(simulation_id) or not ObjectId.is_valid(event_id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(simulation_id)},
            {
                "$addToSet": {"events_generated": event_id},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    async def add_alert_to_simulation(self, simulation_id: str, alert_id: str) -> bool:
        if not ObjectId.is_valid(simulation_id) or not ObjectId.is_valid(alert_id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(simulation_id)},
            {
                "$addToSet": {"alerts_generated": alert_id},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    async def update_results(self, id: str, results: Dict[str, Any]) -> bool:
        if not ObjectId.is_valid(id):
            return False
            
        result = await self.collection.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "results": results,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    async def search_simulations(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search simulations by keyword in name, description, or notes."""
        search_query = {
            "$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"description": {"$regex": query, "$options": "i"}},
                {"notes": {"$regex": query, "$options": "i"}}
            ]
        }
        return await self.find_many(search_query, limit=limit, skip=skip)