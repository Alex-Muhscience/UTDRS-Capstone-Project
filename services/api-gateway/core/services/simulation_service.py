from typing import List, Dict, Any, Optional
from datetime import datetime
from bson import ObjectId
from core.database.repositories.simulation_repository import SimulationRepository
from core.database.repositories.event_repository import EventRepository
from core.database.repositories.alert_repository import AlertRepository
from core.database.repositories.asset_repository import AssetRepository
from core.models.simulation import SimulationCreate, SimulationUpdate, Simulation
from core.models.event import EventCreate
from utils.logger import get_logger
from config import settings

logger = get_logger(__name__)

class SimulationService:
    def __init__(self):
        self.simulation_repo = SimulationRepository()
        self.event_repo = EventRepository()
        self.alert_repo = AlertRepository()
        self.asset_repo = AssetRepository()
        
        # Initialize integration client if URL is configured
        self.core_engine_url = settings.CORE_ENGINE_URL
        self.response_service_url = settings.RESPONSE_SERVICE_URL
    
    async def get_simulations(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get all simulations."""
        return await self.simulation_repo.find_many({}, limit=limit, skip=skip)
    
    async def get_simulation_by_id(self, simulation_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific simulation by ID."""
        return await self.simulation_repo.find_by_id(simulation_id)
    
    async def get_simulation_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a simulation by name."""
        return await self.simulation_repo.find_by_name(name)
    
    async def create_simulation(self, simulation_data: SimulationCreate, user_id: Optional[str] = None) -> str:
        """Create a new simulation."""
        try:
            # Validate that all target assets exist
            for asset_id in simulation_data.target_assets:
                asset = await self.asset_repo.find_by_id(asset_id)
                if not asset:
                    logger.warning(f"Asset with ID {asset_id} not found")
                    raise ValueError(f"Target asset with ID {asset_id} does not exist")
            
            # Check if simulation with same name already exists
            if simulation_data.name:
                existing_sim = await self.simulation_repo.find_by_name(simulation_data.name)
                if existing_sim:
                    logger.warning(f"Simulation with name '{simulation_data.name}' already exists")
                    return str(existing_sim["_id"])
            
            simulation_id = await self.simulation_repo.create_simulation(simulation_data, user_id)
            logger.info(f"Created simulation with ID: {simulation_id}")
            return simulation_id
        except Exception as e:
            logger.error(f"Error creating simulation: {str(e)}")
            raise
    
    async def update_simulation(self, simulation_id: str, simulation_data: SimulationUpdate, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Update an existing simulation."""
        try:
            # Validate that all target assets exist if provided
            if simulation_data.target_assets:
                for asset_id in simulation_data.target_assets:
                    asset = await self.asset_repo.find_by_id(asset_id)
                    if not asset:
                        logger.warning(f"Asset with ID {asset_id} not found")
                        raise ValueError(f"Target asset with ID {asset_id} does not exist")
            
            updated_simulation = await self.simulation_repo.update_simulation(simulation_id, simulation_data, user_id)
            if updated_simulation:
                logger.info(f"Updated simulation with ID: {simulation_id}")
                return updated_simulation
            logger.warning(f"Simulation with ID {simulation_id} not found for update")
            return None
        except Exception as e:
            logger.error(f"Error updating simulation {simulation_id}: {str(e)}")
            raise
    
    async def start_simulation(self, simulation_id: str, user_id: Optional[str] = None) -> bool:
        """Start a simulation."""
        try:
            # Get the simulation
            simulation = await self.simulation_repo.find_by_id(simulation_id)
            if not simulation:
                logger.warning(f"Simulation with ID {simulation_id} not found")
                return False
            
            # Check if simulation is already running
            if simulation.get("status") == "running":
                logger.warning(f"Simulation {simulation_id} is already running")
                return False
            
            # Update simulation status
            result = await self.simulation_repo.update_status(simulation_id, "running", user_id)
            if not result:
                logger.warning(f"Failed to update simulation {simulation_id} status")
                return False
            
            # If integration URLs are configured, start simulation in external services
            if self.core_engine_url:
                await self._start_simulation_in_core_engine(simulation_id)
            
            logger.info(f"Started simulation {simulation_id}")
            return True
        except Exception as e:
            logger.error(f"Error starting simulation {simulation_id}: {str(e)}")
            raise
    
    async def stop_simulation(self, simulation_id: str, user_id: Optional[str] = None) -> bool:
        """Stop a simulation."""
        try:
            # Get the simulation
            simulation = await self.simulation_repo.find_by_id(simulation_id)
            if not simulation:
                logger.warning(f"Simulation with ID {simulation_id} not found")
                return False
            
            # Check if simulation is running
            if simulation.get("status") != "running":
                logger.warning(f"Simulation {simulation_id} is not running")
                return False
            
            # Update simulation status
            result = await self.simulation_repo.update_status(simulation_id, "completed", user_id)
            if not result:
                logger.warning(f"Failed to update simulation {simulation_id} status")
                return False
            
            # If integration URLs are configured, stop simulation in external services
            if self.core_engine_url:
                await self._stop_simulation_in_core_engine(simulation_id)
            
            logger.info(f"Stopped simulation {simulation_id}")
            return True
        except Exception as e:
            logger.error(f"Error stopping simulation {simulation_id}: {str(e)}")
            raise
    
    async def get_simulations_by_status(self, status: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get simulations by status."""
        return await self.simulation_repo.find_by_status(status, limit, skip)
    
    async def get_simulations_by_scenario_type(self, scenario_type: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get simulations by scenario type."""
        return await self.simulation_repo.find_by_scenario_type(scenario_type, limit, skip)
    
    async def get_scheduled_simulations(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get scheduled simulations."""
        return await self.simulation_repo.find_scheduled(limit, skip)
    
    async def get_running_simulations(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get running simulations."""
        return await self.simulation_repo.find_running(limit, skip)
    
    async def search_simulations(self, query: str, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Search simulations by keyword."""
        return await self.simulation_repo.search_simulations(query, limit, skip)
    
    async def update_simulation_results(self, simulation_id: str, results: Dict[str, Any]) -> bool:
        """Update results for a simulation."""
        try:
            result = await self.simulation_repo.update_results(simulation_id, results)
            if result:
                logger.info(f"Updated results for simulation {simulation_id}")
            else:
                logger.warning(f"Failed to update results for simulation {simulation_id}")
            return result
        except Exception as e:
            logger.error(f"Error updating results for simulation {simulation_id}: {str(e)}")
            raise
    
    async def generate_simulation_event(self, simulation_id: str, event_data: EventCreate) -> str:
        """Generate an event as part of a simulation."""
        try:
            # Create the event
            event_id = await self.event_repo.create_event(event_data)
            
            # Associate event with simulation
            await self.simulation_repo.add_event_to_simulation(simulation_id, event_id)
            
            logger.info(f"Generated event {event_id} for simulation {simulation_id}")
            return event_id
        except Exception as e:
            logger.error(f"Error generating event for simulation {simulation_id}: {str(e)}")
            raise
    
    async def associate_alert_with_simulation(self, simulation_id: str, alert_id: str) -> bool:
        """Associate an alert with a simulation."""
        try:
            result = await self.simulation_repo.add_alert_to_simulation(simulation_id, alert_id)
            if result:
                logger.info(f"Associated alert {alert_id} with simulation {simulation_id}")
            else:
                logger.warning(f"Failed to associate alert {alert_id} with simulation {simulation_id}")
            return result
        except Exception as e:
            logger.error(f"Error associating alert with simulation: {str(e)}")
            raise
    
    # Integration methods for core engine
    async def _start_simulation_in_core_engine(self, simulation_id: str) -> bool:
        """Start a simulation in the core engine."""
        # This would be implemented with actual API calls to the core engine
        # For now, just log the intent
        logger.info(f"Would start simulation {simulation_id} in core engine at {self.core_engine_url}")
        return True
    
    async def _stop_simulation_in_core_engine(self, simulation_id: str) -> bool:
        """Stop a simulation in the core engine."""
        logger.info(f"Would stop simulation {simulation_id} in core engine at {self.core_engine_url}")
        return True