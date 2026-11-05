"""Single sign-on settings, as administrators see and change them."""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SsoDomain(BaseModel):
    domain: str
    verified: bool
    # The DNS TXT record that shows the domain is the organisation's.
    record_name: str
    record_value: str


class SsoSettings(BaseModel):
    configured: bool
    issuer: Optional[str] = None
    client_id: Optional[str] = None
    domains: List[SsoDomain] = []
    enabled: bool = False
    # People sign in only with SSO; administrators keep their password.
    enforce: bool = False
    # Someone from a verified domain without an account gets an analyst account.
    auto_provision: bool = False
    updated_at: Optional[datetime] = None
    encryption_available: bool


class SsoUpdate(BaseModel):
    # The provider's issuer, such as https://login.microsoftonline.com/<tenant id>/v2.0 or https://accounts.google.com.
    issuer: Optional[str] = Field(default=None, max_length=300)
    client_id: Optional[str] = Field(default=None, max_length=300)
    # Write-only: never shown again.
    client_secret: Optional[str] = Field(default=None, max_length=1000)
    domains: Optional[List[str]] = Field(default=None, max_length=20)
    enabled: Optional[bool] = None
    enforce: Optional[bool] = None
    auto_provision: Optional[bool] = None


class SsoStart(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    # The dashboard's page the provider sends the person back to (registered at the provider).
    redirect_uri: str = Field(max_length=500)


class SsoRedirect(BaseModel):
    url: str


class SsoCallback(BaseModel):
    code: str = Field(min_length=1, max_length=4000)
    state: str = Field(min_length=10, max_length=200)
