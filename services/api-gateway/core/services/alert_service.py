from typing import List, Dict, Any, Optional
from datetime import datetime
from bson import ObjectId
from core.database.repositories.alert_repository import AlertRepository
from core.database.repositories.event_repository import EventRepository
from core.database.repositories.asset_repository import AssetRepository
from core.models.alert import AlertCreate, AlertUpdate, Alert
from utils.logger import get_logger

logger = get_logger(__name__)

class AlertService:
    def __init__(self):
        self.alert_repo = AlertRepository()
        self.event_repo = EventRepository()
        self.asset_repo = AssetRepository()
    
    async def get_alerts(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get all alerts."""
        return await self.alert_repo.find_many({}, limit=limit, skip=skip)
    
    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific alert by ID."""
        return await self.alert_repo.find_by_id(alert_id)
    
    async def create_alert(self, alert_data: AlertCreate, user_id: Optional[str] = None) -> str:
        """Create a new alert."""
        try:
            alert_id = await self.alert_repo.create_alert(alert_data, user_id)
            logger.info(f"Created alert with ID: {alert_id}")
            return alert_id
        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")
            raise
    
    async def update_alert(self, alert_id: str, alert_data: AlertUpdate, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Update an existing alert."""
        try:
            updated_alert = await self.alert_repo.update_alert(alert_id, alert_data, user_id)
            if updated_alert:
                logger.info(f"Updated alert with ID: {alert_id}")
                return updated_alert
            logger.warning(f"Alert with ID {alert_id} not found for update")
            return None
        except Exception as e:
            logger.error(f"Error updating alert {alert_id}: {str(e)}")
            raise
    
    async def assign_alert(self, alert_id: str, user_id: str) -> bool:
        """Assign an alert to a user."""
        try:
            result = await self.alert_repo.assign_alert(alert_id, user_id)
            if result:
                logger.info(f"Assigned alert {alert_id} to user {user_id}")
            else:
                logger.warning(f"Failed to assign alert {alert_id} to user {user_id}")
            return result
        except Exception as e:
            logger.error(f"Error assigning alert {alert_id} to user {user_id}: {str(e)}")
            raise
    
    async def update_alert_status(self, alert_id: str, status: str, notes: Optional[str] = None) -> bool:
        """Update the status of an alert."""
        try:
            valid_statuses = ["open", "in_progress", "resolved", "closed", "false_positive"]
            if status not in valid_statuses:
                logger.warning(f"Invalid alert status: {status}")
                return False
            
            result = await self.alert_repo.update_status(alert_id, status, notes)
            if result:
                logger.info(f"Updated alert {alert_id} status to {status}")
            else:
                logger.warning(f"Failed to update alert {alert_id} status")
            return result
        except Exception as e:
            logger.error(f"Error updating alert {alert_id} status: {str(e)}")
            raise
    
    async def get_alerts_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get alerts by status."""
        return await self.alert_repo.find_by_status(status, limit, skip)
    
    async def get_alerts_by_severity(self, severity: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get alerts by severity."""
        return await self.alert_repo.find_by_severity(severity, limit, skip)
    
    async def get_alerts_assigned_to_user(self, user_id: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get alerts assigned to a specific user."""
        return await self.alert_repo.find_by_assigned_to(user_id, limit, skip)
    
    async def add_event_to_alert(self, alert_id: str, event_id: str) -> bool:
        """Add an event to an alert."""
        try:
            # Verify event exists
            event = await self.event_repo.find_by_id(event_id)
            if not event:
                logger.warning(f"Event {event_id} not found")
                return False
                
            result = await self.alert_repo.add_event_to_alert(alert_id, event_id)
            if result:
                logger.info(f"Added event {event_id} to alert {alert_id}")
            else:
                logger.warning(f"Failed to add event {event_id} to alert {alert_id}")
            return result
        except Exception as e:
            logger.error(f"Error adding event {event_id} to alert {alert_id}: {str(e)}")
            raise
    
    async def search_alerts(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search alerts by keyword."""
        return await self.alert_repo.search_alerts(query, limit, skip)
    
    async def add_tag_to_alert(self, alert_id: str, tag: str) -> bool:
        """Add a tag to an alert."""
        return await self.alert_repo.add_tag(alert_id, tag)
    
    async def remove_tag_from_alert(self, alert_id: str, tag: str) -> bool:
        """Remove a tag from an alert."""
        return await self.alert_repo.remove_tag(alert_id, tag)