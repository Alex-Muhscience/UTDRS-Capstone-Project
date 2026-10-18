from datetime import datetime

from typing import Any

from pydantic import AliasChoices, BaseModel, Field, model_validator

from core.models.common import IdString


class Tenant(BaseModel):
    """An organisation: the people, data and settings kept apart from every other."""

    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime
    # Everyone must use multi-factor authentication to sign in.
    require_mfa: bool = False

    @model_validator(mode="before")
    @classmethod
    def _security(cls, data: Any) -> Any:
        if isinstance(data, dict) and "security" in data:
            data = {**data, "require_mfa": bool((data.get("security") or {}).get("require_mfa"))}
        return data


class TenantSecurity(BaseModel):
    require_mfa: bool


class TenantUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
