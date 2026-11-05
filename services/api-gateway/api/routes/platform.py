"""The platform console (platform administrators, signed in with a second factor)."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from core.models.user import User
from core.services import audit, platform
from core.tenancy import PLATFORM, tenant_context
from utils.security import require_platform_admin

router = APIRouter()


class OrganisationSummary(BaseModel):
    id: str
    name: str
    slug: Optional[str] = None
    status: str
    created_at: Optional[datetime] = None
    # The deployment's own organisation, where the platform administrators are.
    default: bool = False
    people: int
    administrators: int
    events_last_week: int
    open_alerts: int
    connectors: int
    last_sign_in: Optional[datetime] = None
    mfa_required: bool = False
    # Open critical and high alerts.
    urgent_alerts: int = 0
    # A managed service provider, which looks after other organisations.
    msp: bool = False
    # The service provider that manages this organisation, if any.
    managed_by: Optional[str] = None
    managed_by_name: Optional[str] = None


class OrganisationUser(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: Optional[str] = None
    active: bool
    last_sign_in: Optional[datetime] = None
    platform_admin: bool = False
    mfa: bool = False


class OrganisationDetail(OrganisationSummary):
    users: List[OrganisationUser] = []


class NewOrganisation(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    admin_username: str = Field(min_length=3, max_length=100)
    admin_email: str = Field(min_length=3, max_length=254)


class NewAdministrator(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=3, max_length=254)


class Administrator(BaseModel):
    id: str
    username: str
    email: str


class CreatedAdministrator(BaseModel):
    administrator: Administrator
    # Shown once: give it to them privately; they change it when they sign in.
    temporary_password: str


class CreatedOrganisation(CreatedAdministrator):
    tenant: OrganisationDetail


class OrganisationChange(BaseModel):
    """What to change; anything left out stays as it is."""
    suspended: Optional[bool] = None
    msp: Optional[bool] = None
    # The service provider's organisation id, or "" for none.
    managed_by: Optional[str] = None


class Deletion(BaseModel):
    confirm_name: str = Field(min_length=1, max_length=100)


class PlatformAdmin(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    organisation: Optional[str] = None
    active: bool = True
    mfa: bool = False


class PlatformAdminChange(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    platform_admin: bool


def _refused(error: Exception) -> HTTPException:
    if isinstance(error, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error).strip("'"))
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))


@router.get("/organisations", response_model=List[OrganisationSummary])
async def organisations(admin: User = Depends(require_platform_admin)):
    """Every organisation, with its people, activity, open alerts and connectors."""
    return await platform.summaries()


@router.post("/organisations", response_model=CreatedOrganisation, status_code=status.HTTP_201_CREATED)
async def create_organisation(body: NewOrganisation, request: Request, admin: User = Depends(require_platform_admin)):
    """Create an organisation and its first administrator (a temporary password, shown once)."""
    try:
        return await platform.create_organisation(body.name, body.admin_username, body.admin_email, request, admin)
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.get("/organisations/{tenant_id}", response_model=OrganisationDetail)
async def organisation(tenant_id: str, admin: User = Depends(require_platform_admin)):
    try:
        return await platform.detail(tenant_id)
    except LookupError as e:
        raise _refused(e)


@router.post("/organisations/{tenant_id}/administrators", response_model=CreatedAdministrator, status_code=status.HTTP_201_CREATED)
async def add_administrator(tenant_id: str, body: NewAdministrator, request: Request, admin: User = Depends(require_platform_admin)):
    """Add an administrator to an organisation, such as one locked out of its own."""
    try:
        return await platform.add_administrator(tenant_id, body.username, body.email, request, admin)
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.patch("/organisations/{tenant_id}", response_model=OrganisationDetail)
async def change_organisation(tenant_id: str, body: OrganisationChange, request: Request, admin: User = Depends(require_platform_admin)):
    """
    Suspend an organisation (its people are signed out, and it can do nothing) or reactivate it;
    make it a managed service provider or not; or assign it to one.
    """
    try:
        result = None
        if body.suspended is not None:
            result = await platform.set_status(tenant_id, body.suspended, request, admin)
        if body.msp is not None or body.managed_by is not None:
            result = await platform.set_msp(tenant_id, body.msp, body.managed_by, request, admin)
        return result or await platform.detail(tenant_id)
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.delete("/organisations/{tenant_id}")
async def delete_organisation(tenant_id: str, body: Deletion, request: Request, admin: User = Depends(require_platform_admin)) -> Dict[str, Any]:
    """Delete an organisation and all its data, here and in the core engine, typing its name to confirm. Cannot be undone."""
    try:
        return {"deleted": await platform.delete_organisation(tenant_id, body.confirm_name, request, admin)}
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.get("/admins", response_model=List[PlatformAdmin])
async def platform_admins(admin: User = Depends(require_platform_admin)):
    return await platform.platform_admins()


@router.put("/admins", response_model=List[PlatformAdmin])
async def set_platform_admin(body: PlatformAdminChange, request: Request, admin: User = Depends(require_platform_admin)):
    """Make someone (by username, in any organisation) a platform administrator, or stop."""
    user = await platform.find_user(body.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No user {body.username}")
    try:
        return await platform.set_platform_admin(str(user["_id"]), body.platform_admin, request, admin)
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.get("/audit-log")
async def platform_audit_log(limit: int = 100, admin: User = Depends(require_platform_admin)) -> List[Dict[str, Any]]:
    """The platform's own audit log: sign-ins to unknown accounts, and every platform action."""
    with tenant_context(PLATFORM):
        return await audit.search(limit=max(1, min(limit, 500)))
