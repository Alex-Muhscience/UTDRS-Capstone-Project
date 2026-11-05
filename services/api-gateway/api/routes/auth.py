from datetime import datetime, timedelta
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import AliasChoices, BaseModel, Field, field_validator

from config import settings
from core.database.repositories.user_repository import UserRepository
from core.services import account_email, audit, login_throttle, mfa, sessions, tenants
from core.tenancy import PLATFORM, set_tenant, tenant_context
from core.models.common import IdString
from core.models.user import (
    SessionsEnded,
    User,
    UserCreate,
    UserSelfUpdate,
    UserUpdate,
    validate_password_length,
)
from utils.client_address import client_address
from utils.security import (
    create_access_token,
    get_current_active_user,
    get_password_hash,
    verify_password,
)

router = APIRouter()

# Checked when the username does not exist, so that an unknown name takes as long to
# reject as a wrong password and the response time does not reveal which names exist.
_UNKNOWN_USER_HASH = get_password_hash("not-a-real-password")


class Token(BaseModel):
    """A session, or, when the account has MFA, what is needed to finish signing in."""

    access_token: Optional[str] = None
    token_type: Optional[str] = None
    user: Optional[User] = None
    # The password was right; send a code with mfa_token to /auth/login/mfa within five minutes.
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    # For /auth/refresh, before the access token expires (in expires_in seconds). Works once.
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=200)


class SessionInfo(BaseModel):
    """Where someone is signed in."""

    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    device: str
    address: Optional[str] = None
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    mfa: Optional[str] = None
    # The session this request comes from.
    current: bool = False


class MfaLogin(BaseModel):
    mfa_token: str = Field(max_length=2000)
    # Six digits from the authenticator app, or a recovery code.
    code: str = Field(min_length=6, max_length=20)


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class MfaStatus(BaseModel):
    enabled: bool
    enabled_at: Optional[datetime] = None
    recovery_codes_left: int
    required_by_organisation: bool
    # Whether MFA can be set up here at all (it needs ENCRYPTION_KEY).
    encryption_available: bool


class MfaSetup(BaseModel):
    # For the authenticator app: scan otpauth_uri as a QR code, or type the secret.
    secret: str
    otpauth_uri: str


class RecoveryCodes(BaseModel):
    """Single-use codes for when the phone is not at hand. Shown once: keep them safe."""

    recovery_codes: List[str]


MFA_TOKEN_MINUTES = 5


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    _check_new_password = field_validator("new_password")(validate_password_length)


class AuthConfig(BaseModel):
    allow_registration: bool
    # "join": registering adds an analyst to the existing organisation. "organisation":
    # registering creates a new organisation, with the person as its administrator.
    registration_mode: str
    # Minutes without activity after which a session ends.
    session_idle_minutes: int
    # Whether a forgotten password can be reset by email, and addresses confirmed (email is configured).
    password_reset: bool = False
    # Whether people who register must confirm their email address before signing in.
    email_verification_required: bool = False


class AccountLookup(BaseModel):
    # A username or an email address.
    login: str = Field(min_length=1, max_length=254)


class PasswordReset(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    new_password: str

    _check_new_password = field_validator("new_password")(validate_password_length)


class EmailVerification(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class Accepted(BaseModel):
    message: str


class Registration(UserCreate):
    # The new organisation's name, needed when registration creates organisations.
    organisation: Optional[str] = Field(default=None, min_length=1, max_length=100)


@router.get("/config", response_model=AuthConfig)
async def auth_config() -> Any:
    """What the sign-in page needs to know, such as whether anyone can register."""
    return AuthConfig(
        allow_registration=settings.ALLOW_REGISTRATION, registration_mode=settings.REGISTRATION_MODE,
        session_idle_minutes=settings.SESSION_IDLE_MINUTES,
        password_reset=account_email.available(),
        email_verification_required=_verification_required(),
    )


def _verification_required() -> bool:
    return settings.REQUIRE_EMAIL_VERIFICATION and account_email.available()


async def _account(login: str) -> Optional[dict]:
    login = login.strip()
    repo = UserRepository()
    return await (repo.find_by_email(login) if "@" in login else repo.find_by_username(login))


SENT_IF_KNOWN = "If that account exists and has an email address, a link is on its way. It may take a minute."


@router.post("/forgot-password", response_model=Accepted, status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(body: AccountLookup, request: Request) -> Any:
    """
    Email a link to choose a new password, valid for 30 minutes and once. The answer is
    the same whether or not the account exists. At most three emails an hour per account.
    """
    if not account_email.available():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Email is not set up on this deployment: ask an administrator to reset your password")
    user = await _account(body.login)
    if user:
        sent = await account_email.send_password_reset(user)
        await audit.record("auth.password_reset_requested", request, actor={"type": "anonymous", "name": body.login},
                           target={"type": "user", "id": str(user["_id"]), "name": user["username"]},
                           details={"sent": sent}, tenant_id=user["tenant_id"])
    return {"message": SENT_IF_KNOWN}


@router.post("/reset-password", response_model=Accepted)
async def reset_password(body: PasswordReset, request: Request) -> Any:
    """Choose a new password with the link from the email. Every session of the account ends."""
    try:
        record = await account_email.use(body.token, account_email.RESET)
    except account_email.InvalidToken as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    with tenant_context(record["tenant_id"]):
        repo = UserRepository()
        user = await repo.find_by_id(record["user_id"])
        if not user or not user.get("active", True):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This account cannot be used; ask an administrator")
        await repo.change_password(record["user_id"], body.new_password)
        ended = await sessions.end_all(record["user_id"], "Signed out because the password was reset")
        # Following the link proved the address is theirs.
        await account_email.mark_verified(record["user_id"], record.get("email"))
        await login_throttle.record_success(user["username"], client_address(request))
        await audit.record("auth.password_reset", request, actor=_actor(user), target={"type": "user", "id": record["user_id"], "name": user["username"]},
                           details={"sessions_ended": ended})
    return {"message": "Your password has been changed. Sign in with it."}


@router.post("/verify-email", response_model=Accepted)
async def verify_email(body: EmailVerification, request: Request) -> Any:
    """Confirm an email address with the link sent to it."""
    try:
        record = await account_email.use(body.token, account_email.VERIFY)
    except account_email.InvalidToken as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    if not await account_email.mark_verified(record["user_id"], record.get("email")):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The account's email address has changed since; confirm the new one")
    await audit.record("auth.email_verified", request, actor={"type": "user", "id": record["user_id"]},
                       target={"type": "user", "id": record["user_id"]}, details={"email": record.get("email")}, tenant_id=record["tenant_id"])
    return {"message": "Your email address is confirmed."}


@router.post("/resend-verification", response_model=Accepted, status_code=status.HTTP_202_ACCEPTED)
async def resend_verification(body: AccountLookup) -> Any:
    """Send the link to confirm an email address again (for someone who cannot sign in until they do). The answer never says whether the account exists."""
    user = await _account(body.login)
    if user and not user.get("email_verified"):
        await account_email.send_verification(user)
    return {"message": SENT_IF_KNOWN}


@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.

    Repeated failures are throttled: 429 with Retry-After once an account has had too
    many from one address, or one address too many across accounts.
    """
    address = client_address(request)
    attempted = {"type": "anonymous", "name": form_data.username}
    user_repo = UserRepository()
    user = await user_repo.find_by_username(form_data.username)
    # Attempts on an account are recorded in its organisation's log; attempts on names
    # nobody has, in the platform's.
    audit_tenant = user["tenant_id"] if user else PLATFORM

    wait = await login_throttle.retry_after(form_data.username, address)
    if wait:
        await audit.record("auth.login_throttled", request, actor=attempted, outcome="denied", tenant_id=audit_tenant)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many failed sign-in attempts; try again in "
                f"{-(-wait // 60)} minute{'s' if wait > 60 else ''}"
            ),
            headers={"Retry-After": str(wait)},
        )

    if not verify_password(form_data.password, user["passwordHash"] if user else _UNKNOWN_USER_HASH) or not user:
        await login_throttle.record_failure(form_data.username, address)
        await audit.record("auth.login_failed", request, actor=attempted, outcome="denied", tenant_id=audit_tenant)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("active", True):
        await audit.record(
            "auth.login_failed", request, actor=attempted, outcome="denied", details={"reason": "deactivated"}, tenant_id=audit_tenant
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated; ask an administrator",
        )

    if _verification_required() and user.get("registered_self") and not user.get("email_verified"):
        await audit.record("auth.login_failed", request, actor=attempted, outcome="denied", details={"reason": "email not verified"}, tenant_id=audit_tenant)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Confirm your email address first, with the link we sent you",
            headers={"X-Email-Verification-Required": "true"},
        )

    # From here on, this is the person's organisation's business.
    set_tenant(user["tenant_id"])

    if mfa.enabled(user):
        # The password was right, but the throttle is only reset once the code is too:
        # otherwise the password could be used to reset it between guesses at codes.
        await audit.record("auth.login_password_accepted", request, actor=_actor(user), details={"mfa": "required"})
        token = create_access_token(
            data={"sub": str(user["_id"]), "purpose": "mfa", "tenant": user["tenant_id"]}, expires_delta=timedelta(minutes=MFA_TOKEN_MINUTES)
        )
        return {"mfa_required": True, "mfa_token": token}

    await login_throttle.record_success(form_data.username, address)
    return await _signed_in(request, user)


def _actor(user: dict) -> dict:
    return {"type": "user", "id": str(user["_id"]), "name": user["username"], "role": user.get("role")}


async def _signed_in(request: Request, user: dict, details: Optional[dict] = None) -> dict:
    await UserRepository().update_last_login(str(user["_id"]))
    session_id, refresh_token = await sessions.start(user, request, (details or {}).get("mfa"))
    await audit.record("auth.login_succeeded", request, actor=_actor(user), details={**(details or {}), "session": session_id})
    return _tokens(user, session_id, refresh_token)


def _tokens(user: dict, session_id: str, refresh_token: str) -> dict:
    token = create_access_token(
        data={"sub": str(user["_id"]), "sid": session_id}, expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {
        "access_token": token, "token_type": "bearer", "user": User(**user), "refresh_token": refresh_token,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/refresh", response_model=Token)
async def refresh(body: RefreshRequest) -> Any:
    """
    A new access token, and a new refresh token, for a refresh token. Each refresh token
    works once; using one twice ends the session, as it means it was copied.
    """
    try:
        session, refresh_token = await sessions.refresh(body.refresh_token)
    except sessions.SessionEnded as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e), headers={"WWW-Authenticate": "Bearer"})
    with tenant_context(session["tenant_id"]):
        user = await UserRepository().find_by_id(session["user_id"])
    if not user or not user.get("active", True):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This account has been deactivated")
    return _tokens(user, str(session["_id"]), refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, current_user: User = Depends(get_current_active_user)) -> None:
    """Sign out: this session ends, and its tokens stop working."""
    session_id = getattr(request.state, "session_id", None)
    if session_id:
        await sessions.end(session_id, "You signed out")
        await audit.record("auth.logout", request, target={"type": "session", "id": session_id})


@router.get("/sessions", response_model=List[SessionInfo])
async def my_sessions(request: Request, current_user: User = Depends(get_current_active_user)) -> Any:
    """Where you are signed in, most recently active first."""
    return await sessions.list_for(current_user.id, getattr(request.state, "session_id", None))


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def end_session(session_id: str, request: Request, current_user: User = Depends(get_current_active_user)) -> None:
    """Sign out one of your sessions, such as one on a device you no longer have."""
    if not await sessions.end(session_id, "Signed out from another session", user_id=current_user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    await audit.record("auth.session_ended", request, target={"type": "session", "id": session_id})


@router.post("/sessions/end-others", response_model=SessionsEnded)
async def end_other_sessions(request: Request, current_user: User = Depends(get_current_active_user)) -> Any:
    """Sign out everywhere except here."""
    ended = await sessions.end_all(current_user.id, "Signed out from another session", keep=getattr(request.state, "session_id", None))
    await audit.record("auth.sessions_ended", request, details={"ended": ended})
    return {"ended": ended}


@router.post("/login/mfa", response_model=Token)
async def login_mfa(body: MfaLogin, request: Request) -> Any:
    """
    Finish signing in with a code from the authenticator app, or a recovery code, and the
    mfa_token the password step returned. Wrong codes count towards the same throttle as
    wrong passwords.
    """
    import jwt

    expired = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in again: the time to enter a code has run out")
    try:
        claims = jwt.decode(body.mfa_token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise expired
    if claims.get("purpose") != "mfa" or not claims.get("sub") or not claims.get("tenant"):
        raise expired
    with tenant_context(claims["tenant"]):
        user = await UserRepository().find_by_id(claims["sub"])
    if not user or not user.get("active", True):
        raise expired
    address = client_address(request)
    set_tenant(user["tenant_id"])
    wait = await login_throttle.retry_after(user["username"], address)
    if wait:
        await audit.record("auth.login_throttled", request, actor=_actor(user), outcome="denied")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed sign-in attempts; try again in {-(-wait // 60)} minute{'s' if wait > 60 else ''}",
            headers={"Retry-After": str(wait)},
        )
    used = await mfa.verify(user, body.code)
    if not used:
        await login_throttle.record_failure(user["username"], address)
        await audit.record("auth.mfa_failed", request, actor=_actor(user), outcome="denied")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="That code is not right")
    await login_throttle.record_success(user["username"], address)
    return await _signed_in(request, user, {"mfa": used})


@router.post("/register", response_model=User)
async def register(user_in: Registration, request: Request) -> Any:
    """
    Register. Closed when ALLOW_REGISTRATION is false. With REGISTRATION_MODE "join", the
    person becomes an analyst in the default organisation; with "organisation", a new
    organisation named `organisation` is created and the person is its administrator.
    """
    creating_organisation = settings.REGISTRATION_MODE == "organisation"
    if creating_organisation and not user_in.organisation:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Name the organisation to create")
    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is closed; ask an administrator for an account",
        )
    user_repo = UserRepository()

    # Check if username already exists
    existing_user = await user_repo.find_by_username(user_in.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Check if email already exists
    existing_email = await user_repo.find_by_email(user_in.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    # The person registering never chooses their role: joining makes an analyst, and the
    # founder of a new organisation is its administrator.
    role = "admin" if creating_organisation else "analyst"
    new_account = UserCreate(**user_in.model_dump(exclude={"organisation"}) | {"role": role, "active": True})
    if creating_organisation:
        set_tenant(await tenants.create(user_in.organisation))
    else:
        set_tenant(await tenants.default_id())

    # Create new user
    user_id = await user_repo.create_user(new_account, registered_self=True, email_verified=False)
    new_user = await user_repo.find_by_id(user_id)

    if not new_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )

    await audit.record(
        "auth.registered",
        request,
        actor={"type": "user", "id": user_id, "name": user_in.username, "role": role},
        target={"type": "user", "id": user_id, "name": user_in.username},
        details={"created_organisation": user_in.organisation} if creating_organisation else None,
    )
    await account_email.send_verification(new_user)
    return User(**new_user)


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> Any:
    """Get current user information."""
    return current_user


@router.put("/me", response_model=User)
async def update_user_me(
    user_update: UserSelfUpdate, request: Request, current_user: User = Depends(get_current_active_user)
) -> Any:
    """Update current user information (not role or account status). A new email address has to be confirmed again."""
    user_repo = UserRepository()
    changes = user_update.model_dump(exclude_unset=True)
    email_changed = "email" in changes and changes["email"] != current_user.email
    if email_changed:
        taken = await user_repo.find_by_email(changes["email"])
        if taken and str(taken["_id"]) != current_user.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    updated_user = await user_repo.update_user(
        current_user.id, UserUpdate(**user_update.model_dump(exclude_unset=True))
    )

    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to update user"
        )

    if email_changed:
        await user_repo.set_email_verified(current_user.id, False)
        updated_user = {**updated_user, "email_verified": False}
        await account_email.send_verification(updated_user)
    await audit.record(
        "auth.profile_updated", request, target={"type": "user", "id": current_user.id, "name": current_user.username},
        details={"fields": sorted(user_update.model_dump(exclude_unset=True))},
    )
    return User(**updated_user)


@router.post("/me/send-verification", response_model=Accepted, status_code=status.HTTP_202_ACCEPTED)
async def send_my_verification(current_user: User = Depends(get_current_active_user)) -> Any:
    """Send the link to confirm your email address (again)."""
    if current_user.email_verified:
        return {"message": "Your email address is already confirmed."}
    if not await account_email.send_verification(await _me(current_user)):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Email is not set up on this deployment")
    return {"message": f"A link is on its way to {current_user.email}."}


@router.post("/me/change-password")
async def change_password(
    password_change: PasswordChange,
    request: Request,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """Change current user password."""
    user_repo = UserRepository()
    user = await user_repo.find_by_id(current_user.id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Verify current password
    if not verify_password(password_change.current_password, user["passwordHash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password"
        )

    # Change password
    success = await user_repo.change_password(
        current_user.id, password_change.new_password
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password",
        )

    # Anyone who knew the old password is signed out everywhere but here.
    ended = await sessions.end_all(current_user.id, "Signed out because the password was changed", keep=getattr(request.state, "session_id", None))
    await audit.record("auth.password_changed", request, target={"type": "user", "id": current_user.id, "name": current_user.username},
                       details={"other_sessions_ended": ended})
    return {"message": "Password changed successfully", "other_sessions_ended": ended}


# ---------------------------------------------------------------------------- MFA


async def _me(current_user: User) -> dict:
    user = await UserRepository().find_by_id(current_user.id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    return user


def _person(request: Request) -> None:
    if (getattr(request.state, "principal", None) or {}).get("type") != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Multi-factor authentication is for people, not API keys")


def _refused(error: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))


@router.get("/mfa", response_model=MfaStatus)
async def mfa_status(request: Request, current_user: User = Depends(get_current_active_user)) -> Any:
    """Whether your account has multi-factor authentication, and whether your organisation requires it."""
    _person(request)
    return await mfa.status(await _me(current_user))


@router.post("/mfa/setup", response_model=MfaSetup)
async def mfa_setup(request: Request, current_user: User = Depends(get_current_active_user)) -> Any:
    """Start setting up MFA: a secret for your authenticator app. It is on once you confirm a code from the app."""
    _person(request)
    try:
        return await mfa.start_setup(await _me(current_user))
    except mfa.MfaError as e:
        raise _refused(e)


@router.post("/mfa/confirm", response_model=RecoveryCodes)
async def mfa_confirm(body: MfaCode, request: Request, current_user: User = Depends(get_current_active_user)) -> Any:
    """Turn MFA on with a code from the app. Returns your recovery codes, shown only this once."""
    _person(request)
    try:
        codes = await mfa.confirm_setup(await _me(current_user), body.code)
    except mfa.MfaError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))
    await audit.record("auth.mfa_enabled", request, target={"type": "user", "id": current_user.id, "name": current_user.username})
    return {"recovery_codes": codes}


@router.post("/mfa/recovery-codes", response_model=RecoveryCodes)
async def mfa_new_codes(body: MfaCode, request: Request, current_user: User = Depends(get_current_active_user)) -> Any:
    """Replace your recovery codes (the old ones stop working), with a current code."""
    _person(request)
    try:
        codes = await mfa.new_codes(await _me(current_user), body.code)
    except mfa.MfaError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))
    await audit.record("auth.mfa_codes_replaced", request, target={"type": "user", "id": current_user.id, "name": current_user.username})
    return {"recovery_codes": codes}


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(body: MfaCode, request: Request, current_user: User = Depends(get_current_active_user)) -> None:
    """Turn MFA off, with a current code. Not allowed when your organisation requires it."""
    _person(request)
    try:
        await mfa.disable(await _me(current_user), body.code)
    except mfa.MfaError as e:
        raise _refused(e)
    await audit.record("auth.mfa_disabled", request, target={"type": "user", "id": current_user.id, "name": current_user.username})
