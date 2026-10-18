"""Your organisation."""
from fastapi import APIRouter, Depends, HTTPException, Request, status

from core.models.tenant import Tenant, TenantSecurity, TenantUpdate
from core.models.user import User
from core.database.repositories.user_repository import UserRepository
from core.services import audit, mfa, tenants
from core.tenancy import current_tenant
from utils.security import get_current_active_user, require_admin

router = APIRouter()


@router.get("/current", response_model=Tenant)
async def get_current_tenant(current_user: User = Depends(get_current_active_user)):
    """The organisation you belong to."""
    tenant = await tenants.get(current_tenant())
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return tenant


@router.patch("/current", response_model=Tenant)
async def rename_current_tenant(update: TenantUpdate, request: Request, admin: User = Depends(require_admin)):
    """Rename your organisation (administrators only)."""
    before = await tenants.get(current_tenant())
    tenant = await tenants.rename(current_tenant(), update.name)
    await audit.record(
        "tenant.renamed", request, target={"type": "tenant", "id": current_tenant(), "name": update.name},
        changes={"name": [before["name"] if before else None, update.name]},
    )
    return tenant


@router.patch("/current/security", response_model=Tenant)
async def update_security(body: TenantSecurity, request: Request, admin: User = Depends(require_admin)):
    """
    Require multi-factor authentication for everyone (administrators only). You must have
    it yourself first. People without it can only set it up until they do.
    """
    try:
        await mfa.set_required(body.require_mfa, await UserRepository().find_by_id(admin.id) or {})
    except mfa.MfaError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    await audit.record("tenant.security_changed", request, target={"type": "tenant", "id": current_tenant()}, changes={"require_mfa": body.require_mfa})
    return await tenants.get(current_tenant())
