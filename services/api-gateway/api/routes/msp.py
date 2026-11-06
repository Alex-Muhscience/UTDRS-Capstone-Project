"""A managed service provider's view across the organisations it looks after."""
from datetime import datetime
from typing import List, Literal, Optional

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
    # all: staff reach every client; assigned: only those assigned to each (administrators: always all).
    staff_access: str = "all"
    clients: List[OrganisationSummary] = []


class StaffMember(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: Optional[str] = None
    active: bool = True
    # The clients assigned to them (what they reach when staff access is "assigned").
    clients: List[str] = []


class StaffAccess(BaseModel):
    staff_access: Literal["all", "assigned"]


class Assignment(BaseModel):
    clients: List[str] = Field(default_factory=list, max_length=1000)


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
        "staff_access": msp.staff_access(home),
        "clients": await msp.overview(current_user.tenant_id, current_user) if is_msp else [],
    }


@router.get("/alerts", response_model=List[ClientAlert])
async def client_alerts(limit: int = 50, member: User = Depends(_member)):
    """Open alerts across every organisation you manage, most severe and newest first."""
    if member.permissions is not None and "alerts:read" not in member.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your role does not allow this (alerts:read)")
    return await msp.open_alerts(member.tenant_id, member, max(1, min(limit, 200)))


@router.post("/clients", response_model=CreatedClient, status_code=status.HTTP_201_CREATED)
async def create_client(body: NewClient, request: Request, member: User = Depends(_member)):
    """Create an organisation your service provider manages (its administrators only)."""
    if member.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only your service provider's administrators can add organisations")
    try:
        return await msp.create_client(member.tenant_id, body.name, body.admin_username, body.admin_email, request)
    except msp.MspError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


def _admin(member: User) -> User:
    if member.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only your service provider's administrators can do this")
    return member


@router.put("/staff-access", response_model=StaffAccess)
async def set_staff_access(body: StaffAccess, request: Request, member: User = Depends(_member)):
    """Whether your staff reach every client, or only those assigned to them (administrators only; administrators always reach all)."""
    _admin(member)
    return {"staff_access": await msp.set_staff_access(member.tenant_id, body.staff_access, request)}


@router.get("/staff", response_model=List[StaffMember])
async def staff(member: User = Depends(_member)):
    """Your service provider's people, and the clients assigned to each (administrators only)."""
    _admin(member)
    return await msp.staff(member.tenant_id)


@router.put("/staff/{user_id}/clients", response_model=StaffMember)
async def assign_clients(user_id: str, body: Assignment, request: Request, member: User = Depends(_member)):
    """Set the clients one of your people may work in, when staff access is "assigned" (administrators only)."""
    _admin(member)
    try:
        return await msp.assign(member.tenant_id, user_id, body.clients, request)
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e).strip("'"))
    except msp.MspError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))
