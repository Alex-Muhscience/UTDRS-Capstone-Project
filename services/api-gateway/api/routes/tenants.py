"""Your organisation."""
from fastapi import APIRouter, Depends, HTTPException, Request, status

from core.models.sso import SsoSettings, SsoUpdate
from core.models.tenant import Tenant, TenantSecurity, TenantUpdate
from core.models.user import User
from core.database.repositories.user_repository import UserRepository
from core.services import audit, mfa, sso, tenants
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


# ---------------------------------------------------------------------------- Single sign-on

@router.get("/current/sso", response_model=SsoSettings)
async def get_sso(admin: User = Depends(require_admin)):
    """Single sign-on settings (administrators only). The client secret is never shown."""
    return sso.public(await sso.get_config())


@router.put("/current/sso", response_model=SsoSettings)
async def save_sso(body: SsoUpdate, request: Request, admin: User = Depends(require_admin)):
    """
    Set up or change single sign-on with an OpenID Connect provider (administrators only).
    Register UTDRS at the provider with the dashboard's /sso/callback as its redirect URI.
    Each domain must then be verified with a DNS TXT record before people from it can use it.
    """
    try:
        config = await sso.save(body.model_dump(exclude_unset=True))
    except sso.SsoError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))
    await audit.record("tenant.sso_changed", request, target={"type": "tenant", "id": current_tenant()},
                       details={"fields": sorted(k for k in body.model_dump(exclude_unset=True) if k != "client_secret") + (["client_secret"] if body.client_secret else [])})
    return sso.public(config)


@router.post("/current/sso/domains/{domain}/verify", response_model=SsoSettings)
async def verify_sso_domain(domain: str, request: Request, admin: User = Depends(require_admin)):
    """Check the domain's DNS TXT record, so people from it can sign in with SSO (administrators only)."""
    try:
        config = await sso.verify_domain(domain)
    except sso.SsoError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    await audit.record("tenant.sso_domain_verified", request, target={"type": "tenant", "id": current_tenant()}, details={"domain": domain})
    return sso.public(config)


@router.delete("/current/sso", status_code=status.HTTP_204_NO_CONTENT)
async def remove_sso(request: Request, admin: User = Depends(require_admin)):
    """Turn single sign-on off and forget its settings (administrators only). Passwords work again for everyone."""
    if await sso.remove():
        await audit.record("tenant.sso_removed", request, target={"type": "tenant", "id": current_tenant()})
