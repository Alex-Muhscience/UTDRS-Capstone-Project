"""API keys for scripts, agents and integrations (administrators only)."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status

from core.models.api_key import ApiKey, ApiKeyCreate, ApiKeyWithSecret
from core.models.user import User
from core.services import api_keys, audit
from utils.security import require_admin

router = APIRouter()


@router.get("/scopes", response_model=List[str])
async def list_scopes(admin: User = Depends(require_admin)):
    """The scopes a key can be given: `<area>:read` and `<area>:write`."""
    return api_keys.SCOPES


@router.get("/", response_model=List[ApiKey])
async def list_keys(admin: User = Depends(require_admin)):
    """Every key, newest first, including revoked ones. The keys themselves are never shown."""
    return await api_keys.list_keys()


@router.post("/", response_model=ApiKeyWithSecret, status_code=status.HTTP_201_CREATED)
async def create_key(body: ApiKeyCreate, request: Request, admin: User = Depends(require_admin)):
    """
    Create a key. The response holds the key itself, shown only this once: send it as
    `Authorization: Bearer <key>`. It can do what its scopes allow, and never what
    only administrators can.
    """
    doc, key = await api_keys.create(
        body.name, body.scopes, {"id": admin.id, "name": admin.username}, body.expires_in_days
    )
    await audit.record(
        "api_key.created",
        request,
        target={"type": "api_key", "id": str(doc["_id"]), "name": doc["name"]},
        details={"scopes": doc["scopes"], "prefix": doc["prefix"], "expires_at": doc["expires_at"]},
    )
    return ApiKeyWithSecret(api_key=ApiKey(**doc), key=key)


@router.delete("/{key_id}", response_model=ApiKey)
async def revoke_key(request: Request, key_id: str = Path(...), admin: User = Depends(require_admin)):
    """Revoke a key. It stops working at once; its record is kept."""
    if not await api_keys.revoke(key_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such active API key")
    revoked = next(k for k in await api_keys.list_keys() if str(k["_id"]) == key_id)
    await audit.record("api_key.revoked", request, target={"type": "api_key", "id": key_id, "name": revoked["name"]})
    return ApiKey(**revoked)
