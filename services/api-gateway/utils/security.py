# utils/security.py
import hmac
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError

from config import settings
from core.tenancy import set_tenant
from core.models.user import User
from utils.time import utcnow

# UserRepository is imported inside get_current_user to avoid a circular import.

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login")

# bcrypt only uses the first 72 bytes of a password; longer ones are rejected at
# validation (see core.models.user) rather than silently truncated.
BCRYPT_MAX_PASSWORD_BYTES = 72


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a bcrypt hash."""
    password = plain_password.encode("utf-8")
    if len(password) > BCRYPT_MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(password, hashed_password.encode("utf-8"))
    except ValueError:
        # Malformed stored hash
        return False


def get_password_hash(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token."""
    to_encode = data.copy()

    if expires_delta:
        expire = utcnow() + expires_delta
    else:
        expire = utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    # A unique id, so no two tokens are the same even when issued in the same second.
    to_encode.update({"exp": expire, "iat": utcnow(), "jti": secrets.token_hex(8)})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


INTEGRATION = "integration"  # the role an API key acts with; never an administrator

# What a session may reach before setting up MFA its organisation requires: its own
# account and MFA, and reading (never changing) its organisation.
MFA_SETUP_PATHS = ("/auth/me", "/auth/mfa", "/auth/config", "/auth/passkeys")


def _allowed_before_mfa(request: Request) -> bool:
    path = request.url.path.removeprefix(settings.API_PREFIX)
    return any(path.startswith(allowed) for allowed in MFA_SETUP_PATHS) or (path == "/tenants/current" and request.method == "GET")


# What a read-only person may still change: their own account, nothing of the organisation's.
VIEWER_MAY_CHANGE = ("/auth/me", "/auth/mfa", "/auth/passkeys", "/auth/sessions", "/auth/logout", "/notifications/preferences")


def refuse_viewer_changes(user: User, request: Request) -> None:
    if user.role != "viewer" or request.method in ("GET", "HEAD", "OPTIONS"):
        return
    path = request.url.path.removeprefix(settings.API_PREFIX)
    if not any(path.startswith(allowed) for allowed in VIEWER_MAY_CHANGE):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Read-only access: you can look, but not change anything")


async def refuse_suspended(tenant_id: str) -> None:
    """An organisation the platform has suspended can do nothing until it is reactivated."""
    from core.services import tenants

    if await tenants.is_suspended(tenant_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This organisation has been suspended; contact the service's operator")


async def _api_key_user(request: Request, key: str) -> User:
    from core.services import api_keys

    doc = await api_keys.authenticate(key)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, revoked or expired API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    key_id = str(doc["_id"])
    await refuse_suspended(doc["tenant_id"])
    # Everything this request does from here on is the key's organisation's.
    set_tenant(doc["tenant_id"])
    request.state.principal = {"type": "api_key", "id": key_id, "name": doc["name"], "scopes": doc["scopes"]}
    # Built without validation: an API key is not a person and has no real email address.
    return User.model_construct(
        id=key_id,
        username=f"api-key:{doc['name']}",
        email=f"{doc['prefix']}@api-keys.localdomain",
        firstName=doc["name"],
        lastName=None,
        role=INTEGRATION,
        active=True,
        lastLogin=doc.get("last_used_at"),
        createdAt=doc["created_at"],
        updatedAt=doc["created_at"],
        preferences={},
        tenant_id=doc["tenant_id"],
    )


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> User:
    """The person signed in with this session token, or the API key presented."""
    from core.services.api_keys import PREFIX

    if token.startswith(PREFIX):
        return await _api_key_user(request, token)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str = payload.get("sub")
        # Only session tokens: not the short-lived token between password and MFA code,
        # or any other token signed with the same secret for another purpose.
        if user_id is None or payload.get("purpose") or not payload.get("sid"):
            raise credentials_exception
    except (jwt.PyJWTError, ValidationError):
        raise credentials_exception

    # Import UserRepository here to avoid circular import
    from core.database.repositories.user_repository import UserRepository

    user_repo = UserRepository()
    # Before the tenant is known: the token names the user, and the user names the tenant.
    user = await user_repo.find_by_id_any_tenant(user_id)

    if user is None:
        raise credentials_exception

    # The session must not have been ended (signed out, by an administrator, ...).
    from core.services import sessions

    ended = await sessions.is_active(payload["sid"])
    if ended:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=ended, headers={"WWW-Authenticate": "Bearer"})
    request.state.session_id = payload["sid"]

    if not user.get("active", False):
        # A deactivated account's tokens stop working, so clients sign out.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account has been deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    current = User(**user)
    set_tenant(user["tenant_id"])
    request.state.principal = {"type": "user", "id": current.id, "name": current.username, "role": current.role}
    if current.role == "custom":
        # Their organisation's role decides what they may do, as scopes decide for API keys.
        from core.services import roles

        role = await roles.get(current.custom_role_id)
        current.permissions = list(role.get("permissions") or []) if role else []
        current.custom_role_name = role["name"] if role else None
        request.state.principal["scopes"] = current.permissions
    await refuse_suspended(user["tenant_id"])
    refuse_viewer_changes(current, request)

    # The organisation requires MFA and this account has none: set it up, and nothing else.
    from core.services import mfa

    # A session started with single sign-on or a passkey already had a second factor.
    if not current.mfa_enabled and await mfa.required() and await sessions.method(payload["sid"]) not in ("sso", "passkey"):
        current.mfa_setup_required = True
        if not _allowed_before_mfa(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your organisation requires multi-factor authentication: set it up to continue",
                headers={"X-MFA-Setup-Required": "true"},
            )

    # A service provider's people working in a client organisation.
    from core.services import msp

    target = request.headers.get(msp.HEADER)
    path = request.url.path.removeprefix(settings.API_PREFIX)
    if target and target != user["tenant_id"] and not any(path.startswith(p) for p in msp.NOT_SWITCHED):
        current = await _in_client(request, current, target, payload["sid"])
    return current


async def _in_client(request: Request, current: User, client_id: str, session_id: str) -> User:
    """Switch the request to a client organisation the person's service provider manages, with their role there."""
    from core.services import msp, sessions, tenants

    def refused(detail: str) -> HTTPException:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail, headers={"X-Organisation-Refused": "true"})

    home = await tenants.get(current.tenant_id)
    if not msp.is_msp(home):
        raise refused("Only a service provider's people can work in another organisation")
    client = await msp.client(current.tenant_id, client_id)
    if not client:
        raise refused("Your service provider does not manage that organisation")
    if client.get("status") == "suspended":
        raise refused("This organisation has been suspended; contact the service's operator")
    if (client.get("security") or {}).get("require_mfa") and not current.mfa_enabled and await sessions.method(session_id) not in ("sso", "passkey"):
        raise refused(f"{client['name']} requires multi-factor authentication: set it up on your account first")
    role = msp.ROLE_IN_CLIENTS.get(current.role, "viewer")
    acting = current.model_copy(update={"tenant_id": client_id, "role": role})
    set_tenant(client_id)
    request.state.home_tenant_id = current.tenant_id
    # The client's audit log shows who did it, and for which service provider.
    request.state.principal = {**request.state.principal, "role": role, "organisation": home["name"], "msp_id": current.tenant_id}
    refuse_viewer_changes(acting, request)
    return acting


def require_scope(area: str):
    """
    A router-wide check that an API key may use this area: `<area>:read` for GET and
    HEAD, `<area>:write` for anything else; the same for people with a custom role. Others are governed by their role.
    It depends on authentication, so it can never run before the caller is known.
    """

    async def check(request: Request, current_user: User = Depends(get_current_user)) -> None:
        principal = getattr(request.state, "principal", None) or {}
        needed = f"{area}:{'read' if request.method in ('GET', 'HEAD') else 'write'}"
        if principal.get("type") == "api_key":
            if needed not in principal.get("scopes", []):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This API key does not have the {needed} scope",
                )
        elif "scopes" in principal:
            # A custom role. Areas outside its permissions (people, for one) are governed by the routes themselves.
            from core.services import roles

            if area in roles.AREAS and needed not in principal["scopes"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Your role does not allow this ({needed})",
                )

    return check


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current active user."""
    if not current_user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive"
        )
    return current_user


async def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """The signed-in user, who must be an administrator."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can do this",
        )
    return current_user


async def require_internal_token(
    x_internal_token: Optional[str] = Header(default=None),
) -> None:
    """
    Only UTDRS's own services may call this route.

    They present INTERNAL_API_TOKEN in the X-Internal-Token header, the same shared
    secret the gateway sends to the core engine. The gateway is public, so unlike the
    engine it refuses these routes outright when no token is configured.
    """
    expected = settings.INTERNAL_API_TOKEN
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="INTERNAL_API_TOKEN is not configured",
        )
    if not x_internal_token or not hmac.compare_digest(
        x_internal_token.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token"
        )


async def require_platform_admin(request: Request, current_user: User = Depends(get_current_active_user)) -> User:
    """
    A platform administrator, signed in with a second factor (an authenticator code, a
    recovery code, a passkey or single sign-on): the platform console reaches every organisation.
    """
    if (getattr(request.state, "principal", None) or {}).get("type") != "user" or not current_user.platform_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only platform administrators can do this")
    from core.services import sessions

    if await sessions.method(getattr(request.state, "session_id", "") or "") not in ("totp", "recovery", "passkey", "sso"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="The platform console needs a sign-in with a second factor: set up multi-factor authentication or a passkey, then sign in again",
                            headers={"X-Platform-MFA-Required": "true"})
    return current_user
