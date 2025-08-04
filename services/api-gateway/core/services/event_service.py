from typing import List, Dict, Any, Optional
from datetime import datetime
from bson import ObjectId
from core.database.repositories.event_repository import EventRepository
from core.database.repositories.asset_repository import AssetRepository
from core.models.event import EventCreate, EventUpdate, Event
from utils.logger import get_logger

logger = get_logger(__name__)

class EventService:
    def __init__(self):
        self.event_repo = EventRepository()
        self.asset_repo = AssetRepository()
    
    async def get_events(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get all events."""
        return await self.event_repo.find_many({}, limit=limit, skip=skip)
    
    async def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific event by ID."""
        return await self.event_repo.find_by_id(event_id)
    
    async def create_event(self, event_data: EventCreate) -> str:
        """Create a new event."""
        try:
            # If event has an asset_id, update the asset's last_seen timestamp
            if event_data.asset_id and ObjectId.is_valid(event_data.asset_id):
                await self.asset_repo.update_last_seen(event_data.asset_id)
                
            event_id = await self.event_repo.create_event(event_data)
            logger.info(f"Created event with ID: {event_id}")
            return event_id
        except Exception as e:
            logger.error(f"Error creating event: {str(e)}")
            raise
    
    async def update_event(self, event_id: str, event_data: EventUpdate) -> Optional[Dict[str, Any]]:
        """Update an existing event."""
        try:
            updated_event = await self.event_repo.update_event(event_id, event_data)
            if updated_event:
                logger.info(f"Updated event with ID: {event_id}")
                return updated_event
            logger.warning(f"Event with ID {event_id} not found for update")
            return None
        except Exception as e:
            logger.error(f"Error updating event {event_id}: {str(e)}")
            raise
    
    async def get_events_by_type(self, event_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get events by type."""
        return await self.event_repo.find_by_type(event_type, limit, skip)
    
    async def get_events_by_asset(self, asset_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get events for a specific asset."""
        return await self.event_repo.find_by_asset_id(asset_id, limit, skip)
    
    async def get_events_by_user(self, user_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get events for a specific user."""
        return await self.event_repo.find_by_user_id(user_id, limit, skip)
    
    async def get_events_by_ip(self, ip_address: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get events for a specific IP address."""
        return await self.event_repo.find_by_ip(ip_address, limit, skip)
    
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events."""
        return await self.event_repo.find_recent_events(limit)
    
    async def search_events(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search events by keyword."""
        return await self.event_repo.search_events(query, limit, skip)
    
    async def add_tag_to_event(self, event_id: str, tag: str) -> bool:
        """Add a tag to an event."""
        return await self.event_repo.add_tag(event_id, tag)
    
    async def remove_tag_from_event(self, event_id: str, tag: str) -> bool:
        """Remove a tag from an event."""
        return await self.event_repo.remove_tag(event_id, tag)
    
    async def set_event_severity(self, event_id: str, severity: str) -> bool:
        """Set the severity of an event."""
        try:
            valid_severities = ["critical", "high", "medium", "low", "info"]
            if severity not in valid_severities:
                logger.warning(f"Invalid event severity: {severity}")
                return False
                
            result = await self.event_repo.set_severity(event_id, severity)
            if result:
                logger.info(f"Set event {event_id} severity to {severity}")
            else:
                logger.warning(f"Failed to set event {event_id} severity")
            return result
        except Exception as e:
            logger.error(f"Error setting event {event_id} severity: {str(e)}")
            raise
    
    async def get_events_by_time_range(self, start_time: datetime, end_time: datetime, 
                                    limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get events within a specific time range."""
        return await self.event_repo.find_by_time_range(start_time, end_time, limit, skip)