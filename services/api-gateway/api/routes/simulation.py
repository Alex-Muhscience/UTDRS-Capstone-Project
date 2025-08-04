from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, Body
from typing import List, Optional, Dict, Any
from core.models.user import User
from core.models.simulation import Simulation, SimulationCreate, SimulationUpdate
from core.models.event import EventCreate
from core.services.simulation_service import SimulationService
from utils.security import get_current_active_user

router = APIRouter()

@router.get("/", response_model=List[Simulation])
async def get_simulations(
    status: Optional[str] = None,
    scenario_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get simulations with optional filtering.
    
    - **status**: Filter by simulation status
    - **scenario_type**: Filter by scenario type
    - **limit**: Maximum number of simulations to return
    - **skip**: Number of simulations to skip (for pagination)
    """
    simulation_service = SimulationService()
    
    if status:
        return await simulation_service.get_simulations_by_status(status, limit, skip)
    elif scenario_type:
        return await simulation_service.get_simulations_by_scenario_type(scenario_type, limit, skip)
    else:
        return await simulation_service.get_simulations(limit, skip)

@router.post("/", response_model=Simulation, status_code=status.HTTP_201_CREATED)
async def create_simulation(
    simulation: SimulationCreate,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new simulation.
    """
    simulation_service = SimulationService()
    simulation_id = await simulation_service.create_simulation(simulation, current_user.id)
    
    created_simulation = await simulation_service.get_simulation_by_id(simulation_id)
    if not created_simulation:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create simulation"
        )
    
    return created_simulation

@router.get("/{simulation_id}", response_model=Simulation)
async def get_simulation(
    simulation_id: str = Path(..., title="The ID of the simulation to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific simulation by ID.
    """
    simulation_service = SimulationService()
    simulation = await simulation_service.get_simulation_by_id(simulation_id)
    
    if not simulation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation with ID {simulation_id} not found"
        )
    
    return simulation

@router.put("/{simulation_id}", response_model=Simulation)
async def update_simulation(
    simulation_update: SimulationUpdate,
    simulation_id: str = Path(..., title="The ID of the simulation to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update an existing simulation.
    """
    simulation_service = SimulationService()
    updated_simulation = await simulation_service.update_simulation(simulation_id, simulation_update, current_user.id)
    
    if not updated_simulation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation with ID {simulation_id} not found"
        )
    
    return updated_simulation

@router.post("/start")
async def start_simulation(
    simulation_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start a simulation.
    
    - **simulation_id**: ID of the simulation to start
    """
    simulation_service = SimulationService()
    
    result = await simulation_service.start_simulation(simulation_id, current_user.id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation with ID {simulation_id} not found or already running"
        )
    
    return {"status": "success", "message": f"Started simulation {simulation_id}"}

@router.post("/stop")
async def stop_simulation(
    simulation_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Stop a simulation.
    
    - **simulation_id**: ID of the simulation to stop
    """
    simulation_service = SimulationService()
    
    result = await simulation_service.stop_simulation(simulation_id, current_user.id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation with ID {simulation_id} not found or not running"
        )
    
    return {"status": "success", "message": f"Stopped simulation {simulation_id}"}

@router.get("/scheduled/", response_model=List[Simulation])
async def get_scheduled_simulations(
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get scheduled simulations.
    
    - **limit**: Maximum number of simulations to return
    - **skip**: Number of simulations to skip (for pagination)
    """
    simulation_service = SimulationService()
    return await simulation_service.get_scheduled_simulations(limit, skip)

@router.get("/running/", response_model=List[Simulation])
async def get_running_simulations(
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get running simulations.
    
    - **limit**: Maximum number of simulations to return
    - **skip**: Number of simulations to skip (for pagination)
    """
    simulation_service = SimulationService()
    return await simulation_service.get_running_simulations(limit, skip)

@router.patch("/{simulation_id}/results", response_model=Simulation)
async def update_simulation_results(
    results: Dict[str, Any],
    simulation_id: str = Path(..., title="The ID of the simulation"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update results for a simulation.
    
    - **results**: Dictionary of simulation results
    """
    simulation_service = SimulationService()
    
    result = await simulation_service.update_simulation_results(simulation_id, results)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation with ID {simulation_id} not found"
        )
    
    updated_simulation = await simulation_service.get_simulation_by_id(simulation_id)
    return updated_simulation

@router.post("/{simulation_id}/events")
async def generate_simulation_event(
    event_data: EventCreate,
    simulation_id: str = Path(..., title="The ID of the simulation"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate an event as part of a simulation.
    """
    simulation_service = SimulationService()
    
    try:
        event_id = await simulation_service.generate_simulation_event(simulation_id, event_data)
        return {"status": "success", "message": f"Generated event for simulation {simulation_id}", "event_id": event_id}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{simulation_id}/alerts/{alert_id}")
async def associate_alert_with_simulation(
    simulation_id: str = Path(..., title="The ID of the simulation"),
    alert_id: str = Path(..., title="The ID of the alert"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Associate an alert with a simulation.
    """
    simulation_service = SimulationService()
    
    result = await simulation_service.associate_alert_with_simulation(simulation_id, alert_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation with ID {simulation_id} or alert with ID {alert_id} not found"
        )
    
    return {"status": "success", "message": f"Associated alert {alert_id} with simulation {simulation_id}"}

@router.get("/search/", response_model=List[Simulation])
async def search_simulations(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search simulations by keyword in name, description, or notes.
    
    - **query**: Search term
    - **limit**: Maximum number of simulations to return
    - **skip**: Number of simulations to skip (for pagination)
    """
    simulation_service = SimulationService()
    return await simulation_service.search_simulations(query, limit, skip)