"""A managed service provider's view across the organisations it looks after."""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.routes.platform import Administrator, OrganisationSummary
from core.models.user import User
from core.services import msp, tenants
from utils.security import get_current_active_user

router = APIRouter()


class MspOverview(BaseModel):
    # Whether your organisation is a service provider; if not, the rest is empty.
    msp: bool
    organisation_id: str
    organisation: str
    # Your role in the organisations it manages (as in your own).
    role_in_clients: Optional[str] = None
    clients: List[OrganisationSummary] = []


class ClientAlert(BaseModel):
    id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[datetime] = None
    case_id: Optional[str] = None
    organisation_id: str
    organisation: Optional[str] = None


class NewClient(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # Optional: an administrator of the client's own (a temporary password, shown once).
    admin_username: Optional[str] = Field(None, min_length=3, max_length=100)
    admin_email: Optional[str] = Field(None, min_length=3, max_length=254)


class CreatedClient(BaseModel):
    organisation: OrganisationSummary
    administrator: Optional[Administrator] = None
    temporary_password: Optional[str] = None


async def _member(request: Request, current_user: User = Depends(get_current_active_user)) -> User:
    """Someone (not an API key) in a service provider."""
    if (getattr(request.state, "principal", None) or {}).get("type") != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only people can use the service provider's view")
    if not msp.is_msp(await tenants.get(current_user.tenant_id)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your organisation is not a service provider")
    return current_user


@router.get("", response_model=MspOverview)
async def overview(request: Request, current_user: User = Depends(get_current_active_user)):
    """Whether you work for a service provider and, if so, the organisations it manages, with their numbers."""
    home = await tenants.get(current_user.tenant_id) or {}
    is_msp = msp.is_msp(home) and (getattr(request.state, "principal", None) or {}).get("type") == "user"
    return {
        "msp": is_msp, "organisation_id": current_user.tenant_id, "organisation": home.get("name", ""),
        "role_in_clients": msp.ROLE_IN_CLIENTS.get(current_user.role) if is_msp else None,
        "clients": await msp.overview(current_user.tenant_id) if is_msp else [],
    }


@router.get("/alerts", response_model=List[ClientAlert])
async def client_alerts(limit: int = 50, member: User = Depends(_member)):
    """Open alerts across every organisation you manage, most severe and newest first."""
    if member.permissions is not None and "alerts:read" not in member.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your role does not allow this (alerts:read)")
    return await msp.open_alerts(member.tenant_id, max(1, min(limit, 200)))


@router.post("/clients", response_model=CreatedClient, status_code=status.HTTP_201_CREATED)
async def create_client(body: NewClient, request: Request, member: User = Depends(_member)):
    """Create an organisation your service provider manages (its administrators only)."""
    if member.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only your service provider's administrators can add organisations")
    try:
        return await msp.create_client(member.tenant_id, body.name, body.admin_username, body.admin_email, request)
    except msp.MspError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
