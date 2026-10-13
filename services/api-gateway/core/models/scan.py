from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class ScanInterface(BaseModel):
    name: str = Field(max_length=64)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    mac_address: Optional[str] = Field(default=None, max_length=32)


class ScanReport(BaseModel):
    """A device's inventory, as collected by the scanner agent."""

    hostname: str = Field(min_length=1, max_length=256)
    os: str = Field(min_length=1, max_length=256)
    os_version: Optional[str] = Field(default=None, max_length=256)
    cpu_cores: Optional[int] = Field(default=None, ge=0)
    memory_kb: Optional[int] = Field(default=None, ge=0)
    interfaces: List[ScanInterface] = Field(default_factory=list, max_length=64)
    timestamp: datetime
    # The address the agent connected to the scanner server from.
    reported_from: Optional[str] = Field(default=None, max_length=64)
    # The scanner's own id for this scan, kept on the event for tracing.
    scan_id: Optional[str] = Field(default=None, max_length=64)


class ScanResult(BaseModel):
    asset_id: str
    # True the first time this device is scanned.
    new_device: bool
    # What differs from the device's previous scan: "os", "hardware", "interfaces".
    changes: List[str] = []
    # The event raised for a new device or a changed inventory; none when nothing changed.
    event_id: Optional[str] = None
