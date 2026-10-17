from datetime import datetime

from pydantic import AliasChoices, BaseModel, Field

from core.models.common import IdString


class Tenant(BaseModel):
    """An organisation: the people, data and settings kept apart from every other."""

    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime


class TenantUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
