from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, IPvAnyAddress

from utils.time import utcnow
from core.models.common import IdString, PyObjectId


class AssetBase(BaseModel):
    name: str
    asset_type: str  # server, workstation, network device, etc.
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    status: str = "active"  # active, inactive, decommissioned
    location: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: str = "medium"  # critical, high, medium, low


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    status: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


class AssetInDB(AssetBase):
    id: PyObjectId = Field(default_factory=ObjectId, alias="_id")
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_seen: Optional[datetime] = None
    vulnerabilities: List[str] = []
    tags: List[str] = []
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "60d5ec2dcb43a5e37d0c7513",
                "name": "DC-PROD-01",
                "asset_type": "server",
                "ip_address": "192.168.1.10",
                "mac_address": "00:1A:2B:3C:4D:5E",
                "os": "Windows Server 2019",
                "status": "active",
                "location": "HQ Data Center",
                "owner": "IT Department",
                "department": "Infrastructure",
                "criticality": "critical",
                "created_at": "2023-01-01T00:00:00.000Z",
                "updated_at": "2023-04-01T10:00:00.000Z",
                "last_seen": "2023-04-01T23:00:00.000Z",
                "vulnerabilities": ["CVE-2021-34527", "CVE-2022-21907"],
                "tags": ["domain-controller", "production"],
                "notes": "Primary domain controller for production environment",
                "metadata": {
                    "backup_schedule": "daily",
                    "patching_window": "Sunday 01:00-03:00",
                },
            }
        },
    )


class Asset(AssetBase):
    id: IdString = Field(validation_alias=AliasChoices("_id", "id"))
    created_at: datetime
    updated_at: datetime
    last_seen: Optional[datetime] = None
    vulnerabilities: List[str] = []
    tags: List[str] = []
    notes: Optional[str] = None
    metadata: Dict[str, Any] = {}

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "id": "60d5ec2dcb43a5e37d0c7513",
                "name": "DC-PROD-01",
                "asset_type": "server",
                "ip_address": "192.168.1.10",
                "mac_address": "00:1A:2B:3C:4D:5E",
                "os": "Windows Server 2019",
                "status": "active",
                "location": "HQ Data Center",
                "owner": "IT Department",
                "department": "Infrastructure",
                "criticality": "critical",
                "created_at": "2023-01-01T00:00:00.000Z",
                "updated_at": "2023-04-01T10:00:00.000Z",
                "last_seen": "2023-04-01T23:00:00.000Z",
                "vulnerabilities": ["CVE-2021-34527", "CVE-2022-21907"],
                "tags": ["domain-controller", "production"],
                "notes": "Primary domain controller for production environment",
                "metadata": {
                    "backup_schedule": "daily",
                    "patching_window": "Sunday 01:00-03:00",
                },
            }
        },
    )
