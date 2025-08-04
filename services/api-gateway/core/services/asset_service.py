from typing import List, Dict, Any, Optional
from datetime import datetime
from core.database.repositories.asset_repository import AssetRepository
from core.models.asset import AssetCreate, AssetUpdate, Asset
from utils.logger import get_logger

logger = get_logger(__name__)

class AssetService:
    def __init__(self):
        self.asset_repo = AssetRepository()
    
    async def get_assets(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get all assets."""
        return await self.asset_repo.find_many({}, limit=limit, skip=skip)
    
    async def get_asset_by_id(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific asset by ID."""
        return await self.asset_repo.find_by_id(asset_id)
    
    async def get_asset_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get an asset by name."""
        return await self.asset_repo.find_by_name(name)
    
    async def get_asset_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get an asset by IP address."""
        return await self.asset_repo.find_by_ip(ip_address)
    
    async def get_asset_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get an asset by MAC address."""
        return await self.asset_repo.find_by_mac(mac_address)
    
    async def create_asset(self, asset_data: AssetCreate) -> str:
        """Create a new asset."""
        try:
            # Check if asset with same name, IP, or MAC already exists
            if asset_data.name:
                existing_asset = await self.asset_repo.find_by_name(asset_data.name)
                if existing_asset:
                    logger.warning(f"Asset with name '{asset_data.name}' already exists")
                    return str(existing_asset["_id"])
            
            if asset_data.ip_address:
                existing_asset = await self.asset_repo.find_by_ip(asset_data.ip_address)
                if existing_asset:
                    logger.warning(f"Asset with IP '{asset_data.ip_address}' already exists")
                    return str(existing_asset["_id"])
            
            if asset_data.mac_address:
                existing_asset = await self.asset_repo.find_by_mac(asset_data.mac_address)
                if existing_asset:
                    logger.warning(f"Asset with MAC '{asset_data.mac_address}' already exists")
                    return str(existing_asset["_id"])
            
            asset_id = await self.asset_repo.create_asset(asset_data)
            logger.info(f"Created asset with ID: {asset_id}")
            return asset_id
        except Exception as e:
            logger.error(f"Error creating asset: {str(e)}")
            raise
    
    async def update_asset(self, asset_id: str, asset_data: AssetUpdate) -> Optional[Dict[str, Any]]:
        """Update an existing asset."""
        try:
            updated_asset = await self.asset_repo.update_asset(asset_id, asset_data)
            if updated_asset:
                logger.info(f"Updated asset with ID: {asset_id}")
                return updated_asset
            logger.warning(f"Asset with ID {asset_id} not found for update")
            return None
        except Exception as e:
            logger.error(f"Error updating asset {asset_id}: {str(e)}")
            raise
    
    async def update_asset_last_seen(self, asset_id: str) -> bool:
        """Update the last seen timestamp for an asset."""
        try:
            result = await self.asset_repo.update_last_seen(asset_id)
            if result:
                logger.debug(f"Updated last seen timestamp for asset {asset_id}")
            else:
                logger.warning(f"Failed to update last seen timestamp for asset {asset_id}")
            return result
        except Exception as e:
            logger.error(f"Error updating last seen timestamp for asset {asset_id}: {str(e)}")
            raise
    
    async def add_vulnerability_to_asset(self, asset_id: str, vulnerability: str) -> bool:
        """Add a vulnerability to an asset."""
        try:
            result = await self.asset_repo.add_vulnerability(asset_id, vulnerability)
            if result:
                logger.info(f"Added vulnerability '{vulnerability}' to asset {asset_id}")
            else:
                logger.warning(f"Failed to add vulnerability to asset {asset_id}")
            return result
        except Exception as e:
            logger.error(f"Error adding vulnerability to asset {asset_id}: {str(e)}")
            raise
    
    async def remove_vulnerability_from_asset(self, asset_id: str, vulnerability: str) -> bool:
        """Remove a vulnerability from an asset."""
        try:
            result = await self.asset_repo.remove_vulnerability(asset_id, vulnerability)
            if result:
                logger.info(f"Removed vulnerability '{vulnerability}' from asset {asset_id}")
            else:
                logger.warning(f"Failed to remove vulnerability from asset {asset_id}")
            return result
        except Exception as e:
            logger.error(f"Error removing vulnerability from asset {asset_id}: {str(e)}")
            raise
    
    async def get_assets_by_type(self, asset_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get assets by type."""
        return await self.asset_repo.find_by_type(asset_type, limit, skip)
    
    async def get_assets_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get assets by status."""
        return await self.asset_repo.find_by_status(status, limit, skip)
    
    async def get_assets_by_criticality(self, criticality: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get assets by criticality."""
        return await self.asset_repo.find_by_criticality(criticality, limit, skip)
    
    async def get_assets_by_department(self, department: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get assets by department."""
        return await self.asset_repo.find_by_department(department, limit, skip)
    
    async def search_assets(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search assets by keyword."""
        return await self.asset_repo.search_assets(query, limit, skip)
    
    async def add_tag_to_asset(self, asset_id: str, tag: str) -> bool:
        """Add a tag to an asset."""
        return await self.asset_repo.add_tag(asset_id, tag)
    
    async def remove_tag_from_asset(self, asset_id: str, tag: str) -> bool:
        """Remove a tag from an asset."""
        return await self.asset_repo.remove_tag(asset_id, tag)