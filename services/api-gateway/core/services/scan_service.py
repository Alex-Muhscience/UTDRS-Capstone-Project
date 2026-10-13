"""
Device scan -> asset -> event.

A scan from the device scanner keeps the matching asset up to date. The first scan of
a device, and any scan whose inventory differs from the previous one, also becomes an
event, which goes through detection like any other. An unchanged scan only refreshes
the asset's last-seen time, so a fleet reporting every minute does not flood the
event list.
"""
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from core.database.repositories.asset_repository import AssetRepository
from core.models.event import EventCreate
from core.models.scan import ScanInterface, ScanReport, ScanResult
from core.services.event_service import EventService
from utils.logger import get_logger

logger = get_logger(__name__)

SCANNER_SOURCE = "device-scanner"
SCAN_EVENT_TYPE = "asset_scan"

# For an asset the scanner creates. The scanner cannot tell a server from a laptop,
# so these are starting points for an analyst to correct; scans never overwrite them.
NEW_ASSET_DEFAULTS = {
    "asset_type": "workstation",
    "status": "active",
    "criticality": "medium",
    "location": None,
    "owner": None,
    "department": None,
    "notes": None,
}


def _is_loopback(interface: ScanInterface) -> bool:
    try:
        return ipaddress.ip_address(interface.ip_address or "").is_loopback
    except ValueError:
        return False


def primary_interface(report: ScanReport) -> Optional[ScanInterface]:
    """The interface to show as the asset's address: the first one that is not loopback."""
    candidates = [i for i in report.interfaces if i.ip_address and not _is_loopback(i)]
    return candidates[0] if candidates else None


def inventory(report: ScanReport) -> Dict[str, Any]:
    """What a scan says about the device, in the shape kept on the asset."""
    return {
        "os": report.os,
        "os_version": report.os_version,
        "cpu_cores": report.cpu_cores,
        "memory_kb": report.memory_kb,
        "interfaces": sorted(
            (i.model_dump() for i in report.interfaces), key=lambda i: i["name"]
        ),
    }


def changes_between(previous: Dict[str, Any], current: Dict[str, Any]) -> List[str]:
    changes = []
    if (previous.get("os"), previous.get("os_version")) != (current["os"], current["os_version"]):
        changes.append("os")
    if (previous.get("cpu_cores"), previous.get("memory_kb")) != (
        current["cpu_cores"],
        current["memory_kb"],
    ):
        changes.append("hardware")
    if previous.get("interfaces") != current["interfaces"]:
        changes.append("interfaces")
    return changes


class ScanService:
    def __init__(self):
        self.asset_repo = AssetRepository()
        self.event_service = EventService()

    async def record_scan(self, report: ScanReport) -> Tuple[ScanResult, Optional[EventCreate]]:
        """Apply a scan. Returns the outcome and, when one was raised, the event to analyse."""
        current = inventory(report)
        primary = primary_interface(report)

        seen: Dict[str, Any] = {
            "os": " ".join(part for part in (report.os, report.os_version) if part),
            "metadata.scanner.last_scan_at": report.timestamp,
            "metadata.scanner.reported_from": report.reported_from,
        }
        if primary:
            seen["ip_address"] = primary.ip_address
            if primary.mac_address:
                seen["mac_address"] = primary.mac_address

        before = await self.asset_repo.record_scan(report.hostname, seen, NEW_ASSET_DEFAULTS)
        asset = before or await self.asset_repo.find_by_name(report.hostname)
        asset_id = str(asset["_id"])

        # The inventory is saved after the event, so a scan that is retried because the
        # first attempt failed part-way still raises its event.
        previous = ((before or {}).get("metadata") or {}).get("scanner", {}).get("inventory")
        new_device = previous is None
        changes = [] if new_device else changes_between(previous, current)

        event: Optional[EventCreate] = None
        event_id: Optional[str] = None
        if new_device or changes:
            event = self._event(report, asset_id, primary, new_device, changes)
            event_id = await self.event_service.create_event(event)
            logger.info(f"Scan of {report.hostname} raised event {event_id}")

        await self.asset_repo.update_one(asset_id, {"metadata.scanner.inventory": current})
        return (
            ScanResult(
                asset_id=asset_id, new_device=new_device, changes=changes, event_id=event_id
            ),
            event,
        )

    def _event(
        self,
        report: ScanReport,
        asset_id: str,
        primary: Optional[ScanInterface],
        new_device: bool,
        changes: List[str],
    ) -> EventCreate:
        if new_device:
            description = f"New device discovered: {report.hostname}"
        else:
            description = f"Device inventory changed on {report.hostname}: {', '.join(changes)}"
        return EventCreate(
            timestamp=report.timestamp,
            event_type=SCAN_EVENT_TYPE,
            source=SCANNER_SOURCE,
            source_ip=primary.ip_address if primary else None,
            asset_id=asset_id,
            description=description,
            raw_data={
                **inventory(report),
                "hostname": report.hostname,
                "new_device": new_device,
                "changes": changes,
                "reported_from": report.reported_from,
                "scan_id": report.scan_id,
            },
        )
