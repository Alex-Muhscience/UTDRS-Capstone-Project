from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, Field, field_validator

from core.models.common import IdString
from core.services.api_keys import SCOPES


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: List[str] = Field(min_length=1)
    # Leave out for a key that does not expire.
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=3650)

    @field_validator("scopes")
    @classmethod
    def known_scopes(cls, scopes: List[str]) -> List[str]:
        unknown = sorted(set(scopes) - set(SCOPES))
        if unknown:
            raise ValueError(f"Unknown scopes: {', '.join(unknown)}. Choose from: {', '.join(SCOPES)}")
        return scopes


class ApiKey(BaseModel):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    name: str
    # The start of the key (utdrs_<prefix>_...), to recognise it.
    prefix: str
    scopes: List[str]
    created_by: Dict[str, Any]
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


class ApiKeyWithSecret(BaseModel):
    api_key: ApiKey
    # The key itself. It is shown only in this response and cannot be recovered.
    key: str
