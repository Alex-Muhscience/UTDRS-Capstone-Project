# utils/security.py
from datetime import timedelta
from typing import Any, Dict, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError

from config import settings
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

    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current user from JWT token."""
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
        if user_id is None:
            raise credentials_exception
    except (jwt.PyJWTError, ValidationError):
        raise credentials_exception

    # Import UserRepository here to avoid circular import
    from core.database.repositories.user_repository import UserRepository

    user_repo = UserRepository()
    user = await user_repo.find_by_id(user_id)

    if user is None:
        raise credentials_exception

    if not user.get("active", False):
        # A deactivated account's tokens stop working, so clients sign out.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account has been deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return User(**user)


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
