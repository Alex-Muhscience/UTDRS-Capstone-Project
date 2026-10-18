from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class Check(BaseModel):
    name: str
    ok: bool
    detail: str


class Permission(BaseModel):
    name: str
    used_for: str


class Microsoft365(BaseModel):
    """The Microsoft 365 connection, as administrators see it. Secrets are never shown."""

    connected: bool
    status: Optional[Literal["connected", "error"]] = None
    # consent: UTDRS's app registration, by admin consent; own_app: the organisation's own.
    mode: Optional[Literal["consent", "own_app"]] = None
    azure_tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    organisation_name: Optional[str] = None
    connected_at: Optional[datetime] = None
    last_poll_at: Optional[datetime] = None
    # How many sign-ins, audit records and Defender alerts the last poll brought in.
    last_poll: Dict[str, int] = {}
    errors: Dict[str, str] = {}
    checks: List[Check] = []
    # Whether "Connect with Microsoft" is offered, and whether an own app's secret can be stored.
    consent_available: bool
    encryption_available: bool
    permissions: List[Permission]


class ConsentStart(BaseModel):
    # Where Microsoft sends the administrator back: the dashboard's consent page.
    redirect_uri: str = Field(max_length=500)


class ConsentUrl(BaseModel):
    url: str


class ConsentResult(BaseModel):
    """What Microsoft sent back to the redirect page."""

    state: str = Field(max_length=4000)
    tenant: Optional[str] = Field(None, max_length=100)
    admin_consent: Optional[str] = None
    error: Optional[str] = Field(None, max_length=200)
    error_description: Optional[str] = Field(None, max_length=2000)


class OwnApp(BaseModel):
    azure_tenant_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9.\-]+$")
    client_id: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9\-]+$")
    client_secret: str = Field(min_length=1, max_length=500)


class PollResult(BaseModel):
    counts: Dict[str, int]
    errors: Dict[str, str]
