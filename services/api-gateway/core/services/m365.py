"""
The Microsoft 365 connector: how UTDRS reaches an organisation's Microsoft 365.

An organisation connects in one of two ways:
- **Admin consent** ("Connect with Microsoft"): a Microsoft 365 administrator grants
  UTDRS's own app registration (M365_CLIENT_ID and M365_CLIENT_SECRET) access to their
  tenant. Nothing secret is stored for the organisation.
- **Its own app registration**: the organisation's tenant id, client id and client
  secret. The secret is stored encrypted (utils/crypto.py, bound to the organisation).

Either way UTDRS signs in as the application (OAuth client credentials) and calls
Microsoft Graph. Tokens are cached until shortly before they expire. The connection is
registered with core.services.connectors, so response actions use it without handling
credentials; core.services.m365_ingest fetches sign-ins, audit logs and Defender alerts.
"""
import time
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx
import jwt

from config import settings
from core.database.connection import get_database
from core.services import connectors
from core.tenancy import current_tenant, current_tenant_or_none, scoped
from utils import crypto
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

KIND = {"connector": "m365"}
SCOPE = "https://graph.microsoft.com/.default"
# The Office 365 Management Activity API (Exchange's mailbox audit) is a separate
# resource, with tokens of its own.
MANAGEMENT_SCOPE = "https://manage.office.com/.default"
TOKEN_MARGIN_SECONDS = 120
TIMEOUT = httpx.Timeout(20.0, connect=10.0)
CONSENT_STATE_MINUTES = 15

# What UTDRS asks for, and what each permission is for (application permissions).
PERMISSIONS = [
    ("AuditLog.Read.All", "read sign-ins and directory audit logs"),
    ("Directory.Read.All", "read users, groups and directory roles"),
    ("SecurityAlert.Read.All", "read Microsoft Defender and Entra ID Protection alerts"),
    ("User.ReadWrite.All", "disable and enable accounts, require a new password"),
    ("User.RevokeSessions.All", "sign users out everywhere"),
    ("MailboxSettings.ReadWrite", "remove and restore inbox rules"),
    ("Mail.ReadWrite", "remove phishing email from mailboxes and put it back"),
    ("ActivityFeed.Read", "read Exchange's mailbox audit: inbox rules and forwarding (Office 365 Management APIs)"),
]

# For tests: a transport standing in for Microsoft's sign-in service and Graph.
transport: Optional[httpx.AsyncBaseTransport] = None

_tokens: Dict[Tuple[str, str], Tuple[str, float]] = {}  # (UTDRS tenant, scope) -> (access token, expiry)


class NotConnected(RuntimeError):
    pass


class SignInFailed(RuntimeError):
    """Microsoft refused the application's credentials; the message says why."""


def _connections():
    return scoped(get_database(), "connections")


async def ensure_indexes() -> None:
    await get_database()["connections"].create_index([("tenant_id", 1), ("connector", 1)], unique=True)
    # Events from Microsoft 365 carry Microsoft's id, so polling twice stores them once.
    await get_database()["events"].create_index(
        [("tenant_id", 1), ("raw_data.external_id", 1)], unique=True,
        partialFilterExpression={"raw_data.external_id": {"$type": "string"}}, name="tenant_external_id_unique",
    )


async def get_connection() -> Optional[Dict[str, Any]]:
    return await _connections().find_one(KIND)


def consent_available() -> bool:
    return bool(settings.M365_CLIENT_ID and settings.M365_CLIENT_SECRET)


def _http(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, transport=transport, **kwargs)


def _credentials(connection: Dict[str, Any]) -> Tuple[str, str]:
    if connection["mode"] == "consent":
        if not consent_available():
            raise SignInFailed("UTDRS's Microsoft app registration is not configured (M365_CLIENT_ID, M365_CLIENT_SECRET)")
        return settings.M365_CLIENT_ID, settings.M365_CLIENT_SECRET
    return connection["client_id"], crypto.decrypt(connection["client_secret"], f"m365:{connection['tenant_id']}")


async def _sign_in(azure_tenant_id: str, client_id: str, client_secret: str, scope: str = SCOPE) -> Tuple[str, int]:
    """An access token for Graph, as the application, and how long it lasts."""
    async with _http() as client:
        response = await client.post(
            f"{settings.M365_LOGIN_URL.rstrip('/')}/{azure_tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret, "scope": scope},
        )
    if response.is_error:
        try:
            body = response.json()
            message = body.get("error_description", "").split("\r\n")[0] or body.get("error", "")
        except ValueError:
            message = response.text[:200]
        raise SignInFailed(f"Microsoft refused to sign in ({response.status_code}): {message}")
    body = response.json()
    return body["access_token"], int(body.get("expires_in", 3600))


async def token(connection: Optional[Dict[str, Any]] = None, scope: str = SCOPE) -> str:
    """A current access token for the current organisation's Microsoft 365 (Graph, or `scope`)."""
    key = (current_tenant(), scope)
    cached = _tokens.get(key)
    if cached and cached[1] > time.time():
        return cached[0]
    connection = connection or await get_connection()
    if not connection:
        raise NotConnected("Microsoft 365 is not connected")
    access, lasts = await _sign_in(connection["azure_tenant_id"], *_credentials(connection), scope=scope)
    _tokens[key] = (access, time.time() + lasts - TOKEN_MARGIN_SECONDS)
    return access


def forget_token(tenant_id: Optional[str] = None) -> None:
    tenant_id = tenant_id or current_tenant()
    for key in [k for k in _tokens if k[0] == tenant_id]:
        _tokens.pop(key, None)


async def management() -> Optional[httpx.AsyncClient]:
    """A client for the Office 365 Management Activity API, as the current organisation, or None."""
    connection = await get_connection() if current_tenant_or_none() else None
    if not connection:
        return None
    try:
        access = await token(connection, MANAGEMENT_SCOPE)
    except (SignInFailed, crypto.DecryptionFailed, crypto.EncryptionUnavailable) as e:
        logger.warning(f"Microsoft 365 management sign-in failed: {e}")
        return None
    base = f"{settings.M365_MANAGEMENT_URL.rstrip('/')}/{connection['azure_tenant_id']}/activity/feed"
    return _http(base_url=base, headers={"Authorization": f"Bearer {access}"})


async def graph() -> Optional[httpx.AsyncClient]:
    """A Graph client signed in as the current organisation, or None when it is not connected."""
    if current_tenant_or_none() is None:
        return None
    connection = await get_connection()
    if not connection:
        return None
    try:
        access = await token(connection)
    except (SignInFailed, crypto.DecryptionFailed, crypto.EncryptionUnavailable) as e:
        logger.warning(f"Microsoft 365 sign-in failed: {e}")
        return None
    return _http(base_url=settings.M365_GRAPH_URL.rstrip("/"), headers={"Authorization": f"Bearer {access}"})


# Response actions reach Microsoft 365 through this.
connectors.register("m365", graph)


# ---------------------------------------------------------------------------
# Connecting and disconnecting

def consent_url(user_id: str, redirect_uri: str) -> str:
    """Where to send a Microsoft 365 administrator to grant UTDRS access."""
    state = jwt.encode(
        {"purpose": "m365-consent", "tenant": current_tenant(), "user": user_id, "nonce": uuid.uuid4().hex,
         "exp": utcnow() + timedelta(minutes=CONSENT_STATE_MINUTES)},
        settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM,
    )
    query = httpx.QueryParams({"client_id": settings.M365_CLIENT_ID, "scope": SCOPE, "redirect_uri": redirect_uri, "state": state})
    return f"{settings.M365_LOGIN_URL.rstrip('/')}/organizations/v2.0/adminconsent?{query}"


def check_consent_state(state: str, user_id: str) -> None:
    """The consent came back to the organisation and person who asked for it, recently."""
    try:
        claims = jwt.decode(state, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError as e:
        raise ValueError("The consent link has expired or is not valid; start again") from e
    if claims.get("purpose") != "m365-consent" or claims.get("tenant") != current_tenant() or claims.get("user") != user_id:
        raise ValueError("This consent was started by someone else, or for another organisation")


async def _save(fields: Dict[str, Any], actor: Dict[str, Any]) -> Dict[str, Any]:
    now = utcnow()
    forget_token()
    await _connections().update_one(
        KIND,
        {"$set": {**fields, "status": "connected", "connected_at": now, "connected_by": actor, "errors": {}},
         "$setOnInsert": {"cursors": {}, "last_poll_at": None, "last_poll": {}}},
        upsert=True,
    )
    return await get_connection()


async def connect_by_consent(azure_tenant_id: str, actor: Dict[str, Any]) -> Dict[str, Any]:
    if not consent_available():
        raise SignInFailed("UTDRS's Microsoft app registration is not configured (M365_CLIENT_ID, M365_CLIENT_SECRET)")
    await _sign_in(azure_tenant_id, settings.M365_CLIENT_ID, settings.M365_CLIENT_SECRET)  # the consent took
    return await _save({"mode": "consent", "azure_tenant_id": azure_tenant_id, "client_id": None, "client_secret": None}, actor)


async def connect_own_app(azure_tenant_id: str, client_id: str, client_secret: str, actor: Dict[str, Any]) -> Dict[str, Any]:
    await _sign_in(azure_tenant_id, client_id, client_secret)  # refuse credentials that do not work
    sealed = crypto.encrypt(client_secret, f"m365:{current_tenant()}")
    return await _save({"mode": "own_app", "azure_tenant_id": azure_tenant_id, "client_id": client_id, "client_secret": sealed}, actor)


async def disconnect() -> bool:
    forget_token()
    return bool((await _connections().delete_one(KIND)).deleted_count)


# ---------------------------------------------------------------------------
# Checking what the connection can do

CHECKS = [
    ("Your organisation", "/organization?$select=id,displayName", "Directory.Read.All"),
    ("Sign-ins", "/auditLogs/signIns?$top=1", "AuditLog.Read.All, and an Entra ID P1 or P2 licence"),
    ("Directory audit logs", "/auditLogs/directoryAudits?$top=1", "AuditLog.Read.All"),
    ("Defender alerts", "/security/alerts_v2?$top=1", "SecurityAlert.Read.All"),
]


async def check() -> List[Dict[str, Any]]:
    """Sign in, and try reading each kind of data, to say what works and what is missing."""
    connection = await get_connection()
    if not connection:
        raise NotConnected("Microsoft 365 is not connected")
    forget_token()
    try:
        access = await token(connection)
    except (SignInFailed, crypto.DecryptionFailed) as e:
        return [{"name": "Signing in", "ok": False, "detail": str(e)}]
    results = [{"name": "Signing in", "ok": True, "detail": f"Signed in to tenant {connection['azure_tenant_id']}"}]
    async with _http(base_url=settings.M365_GRAPH_URL.rstrip("/"), headers={"Authorization": f"Bearer {access}"}) as client:
        for name, path, needs in CHECKS:
            try:
                response = await client.get(path)
            except httpx.HTTPError as e:
                results.append({"name": name, "ok": False, "detail": f"Could not reach Microsoft Graph: {e.__class__.__name__}"})
                continue
            if response.is_success:
                detail = "Readable"
                if name == "Your organisation":
                    orgs = response.json().get("value") or [{}]
                    detail = f"Connected to {orgs[0].get('displayName', 'your organisation')}"
                    await _connections().update_one(KIND, {"$set": {"organisation_name": orgs[0].get("displayName")}})
                results.append({"name": name, "ok": True, "detail": detail})
            elif response.status_code in (401, 403):
                results.append({"name": name, "ok": False, "detail": f"Not allowed: needs {needs}"})
            else:
                results.append({"name": name, "ok": False, "detail": f"Microsoft Graph answered {response.status_code}"})
    results.append(await _check_management(connection))
    await _connections().update_one(KIND, {"$set": {"checks": results, "checked_at": utcnow()}})
    return results


async def _check_management(connection: Dict[str, Any]) -> Dict[str, Any]:
    name = "Exchange mailbox audit"
    try:
        access = await token(connection, MANAGEMENT_SCOPE)
    except SignInFailed as e:
        return {"name": name, "ok": False, "detail": str(e)}
    base = f"{settings.M365_MANAGEMENT_URL.rstrip('/')}/{connection['azure_tenant_id']}/activity/feed"
    try:
        async with _http(base_url=base, headers={"Authorization": f"Bearer {access}"}) as client:
            response = await client.get("/subscriptions/list")
    except httpx.HTTPError as e:
        return {"name": name, "ok": False, "detail": f"Could not reach the Office 365 Management API: {e.__class__.__name__}"}
    if response.is_success:
        return {"name": name, "ok": True, "detail": "Readable"}
    if response.status_code in (401, 403):
        return {"name": name, "ok": False, "detail": "Not allowed: needs ActivityFeed.Read (Office 365 Management APIs), and auditing turned on"}
    return {"name": name, "ok": False, "detail": f"The Office 365 Management API answered {response.status_code}"}
