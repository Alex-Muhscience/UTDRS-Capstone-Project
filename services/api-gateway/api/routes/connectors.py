"""Connectors: the services UTDRS reads from and acts through (administrators only)."""
from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.routes.response import actor_of
from core.models.connector import Check, ConsentResult, ConsentStart, ConsentUrl, Microsoft365, OwnApp, PollResult
from core.models.user import User
from core.services import m365, m365_ingest
from utils import crypto
from utils.security import require_admin

router = APIRouter()


async def _status() -> dict:
    connection = await m365.get_connection() or {}
    return {
        "connected": bool(connection),
        **{k: connection.get(k) for k in ("status", "mode", "azure_tenant_id", "client_id", "organisation_name", "connected_at", "last_poll_at")},
        "last_poll": connection.get("last_poll") or {},
        "errors": connection.get("errors") or {},
        "checks": connection.get("checks") or [],
        "consent_available": m365.consent_available(),
        "encryption_available": crypto.available(),
        "permissions": [{"name": name, "used_for": why} for name, why in m365.PERMISSIONS],
    }


def _refused(error: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


@router.get("/microsoft-365", response_model=Microsoft365)
async def microsoft_365(admin: User = Depends(require_admin)):
    """Whether Microsoft 365 is connected, how, and how polling is going."""
    return await _status()


@router.post("/microsoft-365/consent-url", response_model=ConsentUrl)
async def consent_url(body: ConsentStart, admin: User = Depends(require_admin)):
    """Where to send a Microsoft 365 administrator to connect, by admin consent to UTDRS's app."""
    if not m365.consent_available():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Connecting with Microsoft is not set up here; use your own app registration")
    return {"url": m365.consent_url(admin.id, body.redirect_uri)}


@router.post("/microsoft-365/consent", response_model=Microsoft365)
async def consented(body: ConsentResult, request: Request, admin: User = Depends(require_admin)):
    """Finish connecting with what Microsoft sent back after consent; then add the Microsoft 365 detection rules."""
    try:
        m365.check_consent_state(body.state, admin.id)
    except ValueError as e:
        raise _refused(e)
    if body.error or body.admin_consent != "True" or not body.tenant:
        raise _refused(ValueError(f"Consent was not given: {body.error_description or body.error or 'no answer from Microsoft'}"))
    try:
        await m365.connect_by_consent(body.tenant, actor_of(request))
    except m365.SignInFailed as e:
        raise _refused(e)
    await m365_ingest.add_rules(admin.id)
    await m365.check()
    return await _status()


@router.put("/microsoft-365", response_model=Microsoft365)
async def connect_own_app(body: OwnApp, request: Request, admin: User = Depends(require_admin)):
    """
    Connect with your own app registration. The credentials are tried first; the secret is
    stored encrypted, and never shown again. Then the Microsoft 365 detection rules are added.
    """
    if not crypto.available():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Set ENCRYPTION_KEY on the gateway before storing a client secret")
    try:
        await m365.connect_own_app(body.azure_tenant_id, body.client_id, body.client_secret, actor_of(request))
    except m365.SignInFailed as e:
        raise _refused(e)
    await m365_ingest.add_rules(admin.id)
    await m365.check()
    return await _status()


@router.post("/microsoft-365/check", response_model=list[Check])
async def check(admin: User = Depends(require_admin)):
    """Sign in and try reading each kind of data, to see what works and what permission is missing."""
    try:
        return await m365.check()
    except m365.NotConnected as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/microsoft-365/poll", response_model=PollResult)
async def poll_now(admin: User = Depends(require_admin)):
    """Fetch new sign-ins, audit records and Defender alerts now, rather than at the next scheduled poll."""
    if not await m365.get_connection():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Microsoft 365 is not connected")
    result = await m365_ingest.poll()
    if result is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A poll is already running; try again in a moment")
    return result


@router.delete("/microsoft-365", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect(admin: User = Depends(require_admin)):
    """Disconnect Microsoft 365: its credentials are deleted. Events already brought in, and its detection rules, stay."""
    if not await m365.disconnect():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Microsoft 365 is not connected")
