"""
The team directory, and account administration.

Everyone signed in can list colleagues (to see who an alert is assigned to, or
assign it to them). Only administrators can create accounts, change roles,
deactivate accounts or reset passwords.
"""
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, Field

from core.database.repositories.user_repository import UserRepository
from core.models.user import (
    SessionsEnded,
    AdminUserCreate,
    Role,
    User,
    UserAdminUpdate,
    UserCreate,
    UserUpdate,
    UserWithPassword,
)
from core.services import sessions
from core.services.audit import created
from utils.security import get_current_active_user, require_admin

router = APIRouter()


def temporary_password() -> str:
    """A random password to hand to the person, who should change it."""
    return secrets.token_urlsafe(12)


async def find_user_or_404(user_repo: UserRepository, user_id: str) -> dict:
    user = await user_repo.find_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/", response_model=List[User])
async def list_users(
    role: Optional[Role] = None,
    active: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """The people with accounts, newest first. Filter by `role` or `active`."""
    query = {}
    if role is not None:
        query["role"] = role
    if active is not None:
        query["active"] = active
    users = await UserRepository().find_many(query, limit=limit, skip=skip)
    return [User(**user) for user in users]


@router.get("/{user_id}", response_model=User)
async def get_user(
    user_id: str = Path(...),
    current_user: User = Depends(get_current_active_user),
):
    return User(**await find_user_or_404(UserRepository(), user_id))


@router.post("/", response_model=UserWithPassword, status_code=status.HTTP_201_CREATED)
async def create_user(new_user: AdminUserCreate, request: Request, admin: User = Depends(require_admin)):
    """
    Create an account (admins only). The response includes a temporary password,
    shown only this once, for the person to sign in with and then change.
    """
    user_repo = UserRepository()
    if await user_repo.find_by_username(new_user.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    if await user_repo.find_by_email(new_user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    password = temporary_password()
    user_id = await user_repo.create_user(
        UserCreate(**new_user.model_dump(), active=True, password=password)
    )
    created(request, "user", user_id, new_user.username)
    return UserWithPassword(
        user=User(**await find_user_or_404(user_repo, user_id)),
        temporary_password=password,
    )


@router.patch("/{user_id}", response_model=User)
async def update_user(
    update: UserAdminUpdate,
    user_id: str = Path(...),
    admin: User = Depends(require_admin),
):
    """
    Change someone's role or deactivate their account (admins only). You cannot
    change your own role or deactivate yourself, so the administrator making a
    change always remains one. If every administrator is lost anyway, setting
    ADMIN_USERNAME and restarting the gateway restores one.
    """
    user_repo = UserRepository()
    user = await find_user_or_404(user_repo, user_id)
    changes = update.model_dump(exclude_unset=True, exclude_none=True)

    if str(user["_id"]) == admin.id and changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role or deactivate yourself; ask another administrator",
        )

    updated = await user_repo.update_user(user_id, UserUpdate(**changes))
    if changes.get("active") is False:
            await sessions.end_all(user_id, "This account has been deactivated")
    return User(**updated)


async def end_sessions(user_id: str, admin: User, request: Request, reason: str) -> int:
    """End someone's sessions; an administrator acting on themselves keeps the one they are using."""
    keep = getattr(request.state, "session_id", None) if user_id == admin.id else None
    return await sessions.end_all(user_id, reason, keep=keep)


@router.post("/{user_id}/reset-password", response_model=UserWithPassword)
async def reset_password(request: Request, user_id: str = Path(...), admin: User = Depends(require_admin)):
    """
    Give someone a new temporary password (admins only), for example when they have
    forgotten theirs. It is shown only this once.
    """
    user_repo = UserRepository()
    user = await find_user_or_404(user_repo, user_id)
    password = temporary_password()
    await user_repo.change_password(user_id, password)
    await end_sessions(user_id, admin, request, "Signed out because an administrator reset the password")
    return UserWithPassword(user=User(**user), temporary_password=password)


@router.post("/{user_id}/reset-mfa", response_model=User)
async def reset_mfa(request: Request, user_id: str = Path(...), admin: User = Depends(require_admin)):
    """
    Turn off someone's multi-factor authentication (admins only), for example when they
    have lost their phone. If the organisation requires MFA, they set it up again when
    they next sign in.
    """
    from core.services import mfa

    user_repo = UserRepository()
    await find_user_or_404(user_repo, user_id)
    await mfa.reset(user_id)
    await end_sessions(user_id, admin, request, "Signed out because an administrator reset multi-factor authentication")
    return User(**await user_repo.find_by_id(user_id))


@router.post("/{user_id}/sign-out", response_model=SessionsEnded)
async def sign_out_everywhere(request: Request, user_id: str = Path(...), admin: User = Depends(require_admin)):
    """
    Sign someone out of every session (admins only), for example when a device is lost or
    stolen. Administrators signing themselves out keep the session they are using.
    """
    user_repo = UserRepository()
    await find_user_or_404(user_repo, user_id)
    return {"ended": await end_sessions(user_id, admin, request, "Signed out by an administrator")}


class Erasure(BaseModel):
    # The person's current username, typed to confirm: erasing cannot be undone.
    confirm_username: str = Field(min_length=1, max_length=200)


@router.post("/{user_id}/erase", response_model=User)
async def erase_user(body: Erasure, request: Request, user_id: str = Path(...), admin: User = Depends(require_admin)):
    """
    Erase someone's personal data (administrators only), such as on their request: their
    name, username and email become placeholders, their account is deactivated and its sign-in
    methods removed, their sessions end, and their name is replaced wherever it was copied.
    The audit log is kept as it is (it is tamper-evident). This cannot be undone.
    """
    from core.services import erasure

    user_repo = UserRepository()
    user = await find_user_or_404(user_repo, user_id)
    if body.confirm_username != user["username"]:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Type the person's username to confirm")
    try:
        done = await erasure.erase(user_id, admin.id)
    except erasure.ErasureError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    request.state.audit_details = {"erased": done}
    return User(**await user_repo.find_by_id(user_id))
