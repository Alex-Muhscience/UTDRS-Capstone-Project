"""Your organisation."""
from fastapi import APIRouter, Depends, HTTPException, Request, status

from core.models.tenant import Tenant, TenantUpdate
from core.models.user import User
from core.services import audit, tenants
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
