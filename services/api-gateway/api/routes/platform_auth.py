"""
Signing in to the operator console: password, then always a second factor (set up on first
sign-in). Separate from organisations' sign-in in every way: accounts, tokens and sessions.
"""
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.routes.platform import OperatorAccount
from core.services import audit, login_throttle, operators
from core.tenancy import PLATFORM
from utils.security import Operator, require_operator

router = APIRouter()

THROTTLE_PREFIX = "operator:"  # kept apart from organisations' sign-in counts


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class PasswordStep(BaseModel):
    # mfa: enter an authenticator (or recovery) code; enrol: set up an authenticator first.
    step: Literal["mfa", "enrol"]
    step_token: str
    # For enrol: the secret to add to an authenticator app, also as an otpauth:// link (for a QR code).
    secret: Optional[str] = None
    otpauth_uri: Optional[str] = None


class Code(BaseModel):
    step_token: str
    code: str = Field(min_length=6, max_length=20)


class Signed(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    operator: OperatorAccount
    # After setting up an authenticator: recovery codes, shown once.
    recovery_codes: Optional[List[str]] = None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=12, max_length=200)


def _address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _throttled(username: str, request: Request) -> None:
    wait = await login_throttle.retry_after(THROTTLE_PREFIX + username, _address(request))
    if wait:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Too many attempts; try again in {wait} seconds",
                            headers={"Retry-After": str(wait)})


async def _failed(action: str, username: str, request: Request, reason: str) -> None:
    await login_throttle.record_failure(THROTTLE_PREFIX + username, _address(request))
    await audit.record(action, request, actor={"type": "anonymous", "name": username}, outcome="denied", details={"reason": reason}, tenant_id=PLATFORM)


@router.post("/login", response_model=PasswordStep)
async def login(body: Credentials, request: Request):
    """The password. Then an authenticator code (`/mfa`), or, the first time, setting one up (`/enrol`)."""
    await _throttled(body.username, request)
    doc, step = await operators.password_step(body.username, body.password)
    if not doc:
        await _failed("platform.sign_in_failed", body.username, request, "wrong username or password")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong username or password")
    return step


async def _signed_in(doc, method: str, request: Request, codes: Optional[List[str]] = None):
    await login_throttle.record_success(THROTTLE_PREFIX + doc["username"], _address(request))
    signed = await operators.start_session(doc, method, request)
    request.state.principal = {"type": "operator", "id": str(doc["_id"]), "name": doc["username"]}
    await audit.record("platform.signed_in", request, details={"method": method}, tenant_id=PLATFORM)
    return {**signed, "recovery_codes": codes}


@router.post("/mfa", response_model=Signed)
async def second_factor(body: Code, request: Request):
    """An authenticator code, or a recovery code (each works once)."""
    try:
        doc, method = await operators.code_step(body.step_token, body.code)
    except operators.OperatorError as e:
        await _failed("platform.second_factor_failed", "", request, str(e))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    return await _signed_in(doc, method, request)


@router.post("/enrol", response_model=Signed)
async def enrol(body: Code, request: Request):
    """Set up the authenticator (first sign-in, or after a reset): a code from it proves it works. Recovery codes come back once."""
    try:
        doc, codes = await operators.enrol_step(body.step_token, body.code)
    except operators.OperatorError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    return await _signed_in(doc, "totp", request, codes)


@router.post("/refresh", response_model=Signed)
async def refresh(operator: Operator = Depends(require_operator)):
    """A fresh token for the same session, while it lasts (it ends when idle or too old)."""
    return operators.issue(operator.doc, operator.session_id)


@router.get("/me", response_model=OperatorAccount)
async def me(operator: Operator = Depends(require_operator)):
    return operators.public(operator.doc)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(body: PasswordChange, request: Request, operator: Operator = Depends(require_operator)) -> None:
    """Choose a new password (required after a temporary one). At least 12 characters."""
    try:
        await operators.change_password(operator.doc, body.current_password, body.new_password)
    except operators.OperatorError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))
    await audit.record("platform.password_changed", request, tenant_id=PLATFORM)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, operator: Operator = Depends(require_operator)) -> None:
    await operators.end_session(operator.session_id)
    await audit.record("platform.signed_out", request, tenant_id=PLATFORM)
