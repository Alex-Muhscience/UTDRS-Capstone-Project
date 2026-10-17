from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, field_validator

from config import settings
from core.database.repositories.user_repository import UserRepository
from core.services import login_throttle
from core.models.user import (
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
    access_token: str
    token_type: str
    user: User


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    _check_new_password = field_validator("new_password")(validate_password_length)


class AuthConfig(BaseModel):
    allow_registration: bool


@router.get("/config", response_model=AuthConfig)
async def auth_config() -> Any:
    """What the sign-in page needs to know, such as whether anyone can register."""
    return AuthConfig(allow_registration=settings.ALLOW_REGISTRATION)


@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.

    Repeated failures are throttled: 429 with Retry-After once an account has had too
    many from one address, or one address too many across accounts.
    """
    address = client_address(request)
    wait = await login_throttle.retry_after(form_data.username, address)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many failed sign-in attempts; try again in "
                f"{-(-wait // 60)} minute{'s' if wait > 60 else ''}"
            ),
            headers={"Retry-After": str(wait)},
        )

    user_repo = UserRepository()
    user = await user_repo.find_by_username(form_data.username)

    if not verify_password(form_data.password, user["passwordHash"] if user else _UNKNOWN_USER_HASH) or not user:
        await login_throttle.record_failure(form_data.username, address)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    await login_throttle.record_success(form_data.username, address)

    if not user.get("active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated; ask an administrator",
        )

    # Update last login
    await user_repo.update_last_login(str(user["_id"]))

    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={"sub": str(user["_id"])}, expires_delta=access_token_expires
    )

    return {"access_token": token, "token_type": "bearer", "user": User(**user)}


@router.post("/register", response_model=User)
async def register(user_in: UserCreate) -> Any:
    """Register a new user, as an analyst. Closed when ALLOW_REGISTRATION is false."""
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

    # Self-registration always creates an active analyst account. Roles are assigned
    # by an administrator, never chosen by the person registering.
    user_in = user_in.model_copy(update={"role": "analyst", "active": True})

    # Create new user
    user_id = await user_repo.create_user(user_in)
    new_user = await user_repo.find_by_id(user_id)

    if not new_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )

    return User(**new_user)


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> Any:
    """Get current user information."""
    return current_user


@router.put("/me", response_model=User)
async def update_user_me(
    user_update: UserSelfUpdate, current_user: User = Depends(get_current_active_user)
) -> Any:
    """Update current user information (not role or account status)."""
    user_repo = UserRepository()
    updated_user = await user_repo.update_user(
        current_user.id, UserUpdate(**user_update.model_dump(exclude_unset=True))
    )

    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to update user"
        )

    return User(**updated_user)


@router.post("/me/change-password")
async def change_password(
    password_change: PasswordChange,
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

    return {"message": "Password changed successfully"}
