"""Your organisation's custom roles: who may see and do what, area by area."""
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, Field

from core.models.user import User
from core.services import roles
from utils.security import get_current_active_user, require_admin

router = APIRouter()


class PermissionArea(BaseModel):
    area: str
    label: str
    # What :read and :write allow; no write means only administrators change it.
    read: str
    write: Optional[str] = None


class BuiltInRole(BaseModel):
    role: str
    name: str
    description: str
    # Every permission it has; administrators also run the organisation.
    permissions: List[str]


class Catalogue(BaseModel):
    areas: List[PermissionArea]
    built_in: List[BuiltInRole]


class CustomRole(BaseModel):
    id: str
    name: str
    description: str = ""
    permissions: List[str]
    # How many people have it.
    people: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    description: str = Field("", max_length=300)
    permissions: List[str] = Field(default_factory=list, max_length=100)


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=60)
    description: Optional[str] = Field(None, max_length=300)
    permissions: Optional[List[str]] = Field(None, max_length=100)


def _refused(error: Exception) -> HTTPException:
    if isinstance(error, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error).strip("'"))
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))


@router.get("/permissions", response_model=Catalogue)
async def catalogue(current_user: User = Depends(get_current_active_user)) -> Dict:
    """What a role can permit, area by area, and what the built-in roles have."""
    return {
        "areas": [{"area": area, **info} for area, info in roles.AREAS.items()],
        "built_in": [
            {"role": "admin", "name": "Administrator", "permissions": roles.ANALYST_PERMISSIONS,
             "description": "Everything an analyst can do, and runs the organisation: people, roles, connectors, keys, rules, playbooks and settings."},
            {"role": "analyst", "name": "Analyst", "permissions": roles.ANALYST_PERMISSIONS,
             "description": "Investigates and responds: triages alerts, works cases, requests and approves actions."},
            {"role": "viewer", "name": "Read-only", "permissions": roles.VIEWER_PERMISSIONS, "description": "Sees everything an analyst sees, and changes nothing."},
        ],
    }


@router.get("", response_model=List[CustomRole])
async def list_roles(current_user: User = Depends(get_current_active_user)):
    """Your organisation's custom roles, with how many people have each."""
    return await roles.list_roles()


@router.post("", response_model=CustomRole, status_code=status.HTTP_201_CREATED)
async def create_role(body: RoleCreate, request: Request, admin: User = Depends(require_admin)):
    """Create a role from permissions (administrators only). Changing an area includes seeing it."""
    try:
        return await roles.create(body.name, body.description, body.permissions, {"id": admin.id, "name": admin.username})
    except roles.RoleError as e:
        raise _refused(e)


@router.patch("/{role_id}", response_model=CustomRole)
async def update_role(body: RoleUpdate, role_id: str = Path(...), admin: User = Depends(require_admin)):
    """Change a role (administrators only); everyone with it has the new permissions at once."""
    try:
        return await roles.update(role_id, body.name, body.description, body.permissions)
    except (roles.RoleError, LookupError) as e:
        raise _refused(e)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: str = Path(...), admin: User = Depends(require_admin)) -> None:
    """Delete a role nobody has (administrators only)."""
    try:
        await roles.delete(role_id)
    except (roles.RoleError, LookupError) as e:
        raise _refused(e)
