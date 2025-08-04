from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional
from core.models.user import User
from core.models.asset import Asset, AssetCreate, AssetUpdate
from core.services.asset_service import AssetService
from utils.security import get_current_active_user

router = APIRouter()

@router.get("/", response_model=List[Asset])
async def get_assets(
    asset_type: Optional[str] = None,
    status: Optional[str] = None,
    criticality: Optional[str] = None,
    department: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get assets with optional filtering.
    
    - **asset_type**: Filter by asset type
    - **status**: Filter by asset status
    - **criticality**: Filter by asset criticality
    - **department**: Filter by department
    - **limit**: Maximum number of assets to return
    - **skip**: Number of assets to skip (for pagination)
    """
    asset_service = AssetService()
    
    if asset_type:
        return await asset_service.get_assets_by_type(asset_type, limit, skip)
    elif status:
        return await asset_service.get_assets_by_status(status, limit, skip)
    elif criticality:
        return await asset_service.get_assets_by_criticality(criticality, limit, skip)
    elif department:
        return await asset_service.get_assets_by_department(department, limit, skip)
    else:
        return await asset_service.get_assets(limit, skip)

@router.post("/", response_model=Asset, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset: AssetCreate,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new asset.
    """
    asset_service = AssetService()
    asset_id = await asset_service.create_asset(asset)
    
    created_asset = await asset_service.get_asset_by_id(asset_id)
    if not created_asset:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create asset"
        )
    
    return created_asset

@router.get("/{asset_id}", response_model=Asset)
async def get_asset(
    asset_id: str = Path(..., title="The ID of the asset to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific asset by ID.
    """
    asset_service = AssetService()
    asset = await asset_service.get_asset_by_id(asset_id)
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found"
        )
    
    return asset

@router.put("/{asset_id}", response_model=Asset)
async def update_asset(
    asset_update: AssetUpdate,
    asset_id: str = Path(..., title="The ID of the asset to update"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update an existing asset.
    """
    asset_service = AssetService()
    updated_asset = await asset_service.update_asset(asset_id, asset_update)
    
    if not updated_asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found"
        )
    
    return updated_asset

@router.get("/name/{name}", response_model=Asset)
async def get_asset_by_name(
    name: str = Path(..., title="The name of the asset to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get an asset by name.
    """
    asset_service = AssetService()
    asset = await asset_service.get_asset_by_name(name)
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with name '{name}' not found"
        )
    
    return asset

@router.get("/ip/{ip_address}", response_model=Asset)
async def get_asset_by_ip(
    ip_address: str = Path(..., title="The IP address of the asset to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get an asset by IP address.
    """
    asset_service = AssetService()
    asset = await asset_service.get_asset_by_ip(ip_address)
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with IP address '{ip_address}' not found"
        )
    
    return asset

@router.get("/mac/{mac_address}", response_model=Asset)
async def get_asset_by_mac(
    mac_address: str = Path(..., title="The MAC address of the asset to get"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get an asset by MAC address.
    """
    asset_service = AssetService()
    asset = await asset_service.get_asset_by_mac(mac_address)
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with MAC address '{mac_address}' not found"
        )
    
    return asset

@router.patch("/{asset_id}/vulnerabilities/add")
async def add_vulnerability_to_asset(
    vulnerability: str,
    asset_id: str = Path(..., title="The ID of the asset"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a vulnerability to an asset.
    
    - **vulnerability**: Vulnerability identifier (e.g., CVE number)
    """
    asset_service = AssetService()
    
    result = await asset_service.add_vulnerability_to_asset(asset_id, vulnerability)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found"
        )
    
    return {"status": "success", "message": f"Vulnerability '{vulnerability}' added to asset {asset_id}"}

@router.patch("/{asset_id}/vulnerabilities/remove")
async def remove_vulnerability_from_asset(
    vulnerability: str,
    asset_id: str = Path(..., title="The ID of the asset"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Remove a vulnerability from an asset.
    
    - **vulnerability**: Vulnerability identifier (e.g., CVE number)
    """
    asset_service = AssetService()
    
    result = await asset_service.remove_vulnerability_from_asset(asset_id, vulnerability)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found or vulnerability '{vulnerability}' not present"
        )
    
    return {"status": "success", "message": f"Vulnerability '{vulnerability}' removed from asset {asset_id}"}

@router.post("/{asset_id}/tags/{tag}")
async def add_tag_to_asset(
    asset_id: str = Path(..., title="The ID of the asset"),
    tag: str = Path(..., title="The tag to add"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Add a tag to an asset.
    """
    asset_service = AssetService()
    
    result = await asset_service.add_tag_to_asset(asset_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' added to asset {asset_id}"}

@router.delete("/{asset_id}/tags/{tag}")
async def remove_tag_from_asset(
    asset_id: str = Path(..., title="The ID of the asset"),
    tag: str = Path(..., title="The tag to remove"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Remove a tag from an asset.
    """
    asset_service = AssetService()
    
    result = await asset_service.remove_tag_from_asset(asset_id, tag)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found or tag '{tag}' not present"
        )
    
    return {"status": "success", "message": f"Tag '{tag}' removed from asset {asset_id}"}

@router.patch("/{asset_id}/lastseen")
async def update_asset_last_seen(
    asset_id: str = Path(..., title="The ID of the asset"),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update the last seen timestamp for an asset.
    """
    asset_service = AssetService()
    
    result = await asset_service.update_asset_last_seen(asset_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found"
        )
    
    return {"status": "success", "message": f"Updated last seen timestamp for asset {asset_id}"}

@router.get("/search/", response_model=List[Asset])
async def search_assets(
    query: str,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search assets by keyword in name or notes.
    
    - **query**: Search term
    - **limit**: Maximum number of assets to return
    - **skip**: Number of assets to skip (for pagination)
    """
    asset_service = AssetService()
    return await asset_service.search_assets(query, limit, skip)