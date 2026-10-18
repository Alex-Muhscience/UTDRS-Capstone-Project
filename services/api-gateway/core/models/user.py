from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from bson import ObjectId

from core.models.common import IdString, PyObjectId
from pydantic import AliasChoices, BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from utils.time import utcnow


# Admins manage users and detection content (rules, simulations); analysts triage
# alerts and work with events and assets. Everyone signed in can read everything.
Role = Literal["admin", "analyst"]
ADMIN: Role = "admin"
ANALYST: Role = "analyst"


class UserBase(BaseModel):
    username: str
    email: EmailStr
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    role: str = ANALYST
    active: bool = True


def validate_password_length(password: str) -> str:
    """At least 8 characters, and at most the 72 bytes that bcrypt can use."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 bytes long")
    return password


class UserCreate(UserBase):
    password: str

    _check_password = field_validator("password")(validate_password_length)


class UserInDB(UserBase):
    id: PyObjectId = Field(default_factory=ObjectId, alias="_id")
    passwordHash: str
    lastLogin: Optional[datetime] = None
    createdAt: datetime = Field(default_factory=utcnow)
    updatedAt: datetime = Field(default_factory=utcnow)
    preferences: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "60d5ec2dcb43a5e37d0c7513",
                "username": "analyst1",
                "email": "analyst1@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "role": "analyst",
                "active": True,
                "passwordHash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                "lastLogin": "2023-04-01T10:00:00.000Z",
                "createdAt": "2023-01-01T00:00:00.000Z",
                "updatedAt": "2023-04-01T10:00:00.000Z",
                "preferences": {"theme": "dark", "alertsPerPage": 20},
            }
        },
    )


class User(UserBase):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    # The organisation the account belongs to.
    tenant_id: Optional[str] = None
    lastLogin: Optional[datetime] = None
    createdAt: datetime
    updatedAt: datetime
    preferences: Dict[str, Any] = {}
    # Whether a second factor is needed to sign in (the secret itself is never shown).
    mfa_enabled: bool = False
    # Signed in, but the organisation requires MFA and this account has none yet: the
    # session can only set it up.
    mfa_setup_required: bool = False

    @model_validator(mode="before")
    @classmethod
    def _mfa(cls, data: Any) -> Any:
        if isinstance(data, dict) and "mfa" in data:
            data = {**data, "mfa_enabled": bool((data.get("mfa") or {}).get("enabled"))}
        return data

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "id": "60d5ec2dcb43a5e37d0c7513",
                "username": "analyst1",
                "email": "analyst1@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "role": "analyst",
                "active": True,
                "lastLogin": "2023-04-01T10:00:00.000Z",
                "createdAt": "2023-01-01T00:00:00.000Z",
                "updatedAt": "2023-04-01T10:00:00.000Z",
                "preferences": {"theme": "dark", "alertsPerPage": 20},
            }
        },
    )


class UserUpdate(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    preferences: Optional[Dict[str, Any]] = None


class UserSelfUpdate(BaseModel):
    """The fields users may change on their own account. Role and status are admin-only."""

    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[EmailStr] = None
    preferences: Optional[Dict[str, Any]] = None


class UserAdminUpdate(BaseModel):
    """What an administrator can change on someone else's account."""

    role: Optional[Role] = None
    active: Optional[bool] = None


class AdminUserCreate(BaseModel):
    """An account created by an administrator; the password is generated."""

    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    role: Role = ANALYST


class UserWithPassword(BaseModel):
    """A new or reset account, with its one-time password. Shown once."""

    user: User
    temporary_password: str
