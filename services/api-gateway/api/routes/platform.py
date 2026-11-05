"""The platform console: for operators (core/services/operators.py), never an organisation's accounts."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from core.services import audit, operators, platform
from core.tenancy import PLATFORM, tenant_context
from utils.security import Operator, require_operator

router = APIRouter()


class OrganisationSummary(BaseModel):
    id: str
    name: str
    slug: Optional[str] = None
    status: str
    created_at: Optional[datetime] = None
    # The default organisation: where people who register without an organisation go.
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


class OperatorAccount(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    active: bool = True
    # Whether their authenticator is set up (it must be, before they can do anything).
    mfa: bool = False
    # Signed in with a temporary password they have not changed yet.
    must_change_password: bool = False
    created_at: Optional[datetime] = None
    last_sign_in: Optional[datetime] = None


class NewOperator(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=3, max_length=254)


class CreatedOperator(BaseModel):
    operator: OperatorAccount
    # Shown once: they change it, and set up an authenticator, when they first sign in.
    temporary_password: str


class OperatorChange(BaseModel):
    active: bool


def _refused(error: Exception) -> HTTPException:
    if isinstance(error, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error).strip("'"))
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))


@router.get("/organisations", response_model=List[OrganisationSummary])
async def organisations(admin: Operator = Depends(require_operator)):
    """Every organisation, with its people, activity, open alerts and connectors."""
    return await platform.summaries()


@router.post("/organisations", response_model=CreatedOrganisation, status_code=status.HTTP_201_CREATED)
async def create_organisation(body: NewOrganisation, request: Request, admin: Operator = Depends(require_operator)):
    """Create an organisation and its first administrator (a temporary password, shown once)."""
    try:
        return await platform.create_organisation(body.name, body.admin_username, body.admin_email, request, admin)
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.get("/organisations/{tenant_id}", response_model=OrganisationDetail)
async def organisation(tenant_id: str, admin: Operator = Depends(require_operator)):
    try:
        return await platform.detail(tenant_id)
    except LookupError as e:
        raise _refused(e)


@router.post("/organisations/{tenant_id}/administrators", response_model=CreatedAdministrator, status_code=status.HTTP_201_CREATED)
async def add_administrator(tenant_id: str, body: NewAdministrator, request: Request, admin: Operator = Depends(require_operator)):
    """Add an administrator to an organisation, such as one locked out of its own."""
    try:
        return await platform.add_administrator(tenant_id, body.username, body.email, request, admin)
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.patch("/organisations/{tenant_id}", response_model=OrganisationDetail)
async def change_organisation(tenant_id: str, body: OrganisationChange, request: Request, admin: Operator = Depends(require_operator)):
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
async def delete_organisation(tenant_id: str, body: Deletion, request: Request, admin: Operator = Depends(require_operator)) -> Dict[str, Any]:
    """Delete an organisation and all its data, here and in the core engine, typing its name to confirm. Cannot be undone."""
    try:
        return {"deleted": await platform.delete_organisation(tenant_id, body.confirm_name, request, admin)}
    except (platform.PlatformError, LookupError) as e:
        raise _refused(e)


@router.get("/operators", response_model=List[OperatorAccount])
async def list_operators(admin: Operator = Depends(require_operator)):
    """Everyone who can use the operator console."""
    return await operators.list_all()


@router.post("/operators", response_model=CreatedOperator, status_code=status.HTTP_201_CREATED)
async def add_operator(body: NewOperator, request: Request, admin: Operator = Depends(require_operator)):
    """Add an operator, with a temporary password shown once; they set up an authenticator at first sign-in."""
    password = operators.temporary_password()
    try:
        doc = await operators.create(body.username, body.email, password, {"id": admin.id, "name": admin.username})
    except operators.OperatorError as e:
        raise _refused(e)
    await audit.record("platform.operator_added", request, target={"type": "operator", "id": str(doc["_id"]), "name": doc["username"]}, tenant_id=PLATFORM)
    return {"operator": operators.public(doc), "temporary_password": password}


@router.patch("/operators/{operator_id}", response_model=OperatorAccount)
async def change_operator(operator_id: str, body: OperatorChange, request: Request, admin: Operator = Depends(require_operator)):
    """Deactivate an operator (their sessions end) or reactivate them. Never yourself, nor the last active one."""
    try:
        result = await operators.set_active(operator_id, body.active, {"id": admin.id, "name": admin.username})
    except (operators.OperatorError, LookupError) as e:
        raise _refused(e)
    await audit.record("platform.operator_reactivated" if body.active else "platform.operator_deactivated", request,
                       target={"type": "operator", "id": operator_id, "name": result["username"]}, tenant_id=PLATFORM)
    return result


@router.post("/operators/{operator_id}/reset", response_model=CreatedOperator)
async def reset_operator(operator_id: str, request: Request, admin: Operator = Depends(require_operator)):
    """A new temporary password and no authenticator, for an operator who lost theirs: they set both up again."""
    try:
        result, password = await operators.reset(operator_id, {"id": admin.id, "name": admin.username})
    except (operators.OperatorError, LookupError) as e:
        raise _refused(e)
    await audit.record("platform.operator_reset", request, target={"type": "operator", "id": operator_id, "name": result["username"]}, tenant_id=PLATFORM)
    return {"operator": result, "temporary_password": password}


@router.get("/audit-log")
async def platform_audit_log(limit: int = 100, admin: Operator = Depends(require_operator)) -> List[Dict[str, Any]]:
    """The platform's own audit log: sign-ins to unknown accounts, and every platform action."""
    with tenant_context(PLATFORM):
        return await audit.search(limit=max(1, min(limit, 500)))
