"""
Managed service providers (MSPs): organisations that look after other organisations.

A platform administrator marks an organisation as an MSP; the MSP then creates client
organisations, or a platform administrator assigns existing ones to it (`managed_by` on the
client). The MSP's people work in a client by sending the `X-UTDRS-Organisation` header with
the client's id (utils/security.py switches the request to it), with the same role there as
in the MSP: its administrators administer every client, its analysts are analysts there, its
read-only people can only look. Everything they do in a client is in the client's own audit
log, under their name and the MSP's.

A client's administrators see which MSP manages them, and can end that at any time.
"""
from typing import Any, Dict, List, Optional

from bson import ObjectId

from core.database.connection import get_database
from core.services import audit, tenants
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

HEADER = "X-UTDRS-Organisation"
# What MSP staff may do in a client, by their role in the MSP.
ROLE_IN_CLIENTS = {"admin": "admin", "analyst": "analyst", "viewer": "viewer"}
# Paths that are about the person or the MSP itself, never switched to a client.
NOT_SWITCHED = ("/auth/", "/notifications/preferences", "/platform", "/msp", "/api-keys")
OPEN_STATUSES = ["open", "in_progress"]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class MspError(ValueError):
    """The MSP action cannot be done; the message says why, for people."""


def is_msp(tenant: Optional[Dict[str, Any]]) -> bool:
    return bool(tenant and tenant.get("msp"))


async def client(msp_id: str, client_id: str) -> Optional[Dict[str, Any]]:
    """The client organisation, if this MSP manages it."""
    if not ObjectId.is_valid(client_id):
        return None
    found = await tenants.get(client_id)
    return found if found and found.get("managed_by") == msp_id else None


async def client_ids(msp_id: str) -> List[str]:
    return [str(t["_id"]) async for t in get_database()["tenants"].find({"managed_by": msp_id}, {"_id": 1})]


async def overview(msp_id: str) -> List[Dict[str, Any]]:
    """Each client, with what an MSP needs to see at a glance (as the platform console shows)."""
    from core.services import platform

    ids = await client_ids(msp_id)
    return await platform.summaries(ids) if ids else []


async def open_alerts(msp_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Open alerts across every client, most severe and newest first, each with its client."""
    ids = await client_ids(msp_id)
    if not ids:
        return []
    names = {str(t["_id"]): t["name"] async for t in get_database()["tenants"].find({"_id": {"$in": [ObjectId(i) for i in ids]}}, {"name": 1})}
    found = await get_database()["alerts"].find(
        {"tenant_id": {"$in": ids}, "status": {"$in": OPEN_STATUSES}},
        {"title": 1, "severity": 1, "status": 1, "created_at": 1, "tenant_id": 1, "case_id": 1},
    ).sort("created_at", -1).limit(500).to_list(None)
    found.sort(key=lambda a: (SEVERITY_ORDER.get(a.get("severity"), 9), -(a["created_at"].timestamp() if a.get("created_at") else 0)))
    return [{"id": str(a["_id"]), "title": a.get("title"), "severity": a.get("severity"), "status": a.get("status"),
             "created_at": a.get("created_at"), "case_id": a.get("case_id"), "organisation_id": a["tenant_id"],
             "organisation": names.get(a["tenant_id"])} for a in found[:limit]]


async def _record(action: str, request, msp_id: str, client_id: str, details: Optional[Dict[str, Any]] = None) -> None:
    """In the MSP's log and the client's: both should see it."""
    target = {"type": "tenant", "id": client_id}
    await audit.record(action, request, target=target, details=details, tenant_id=msp_id)
    await audit.record(action, request, target=target, details=details, tenant_id=client_id)


async def create_client(msp_id: str, name: str, admin_username: Optional[str], admin_email: Optional[str], request) -> Dict[str, Any]:
    """A client organisation this MSP manages, optionally with an administrator of its own (a temporary password, shown once)."""
    from core.services import platform

    if not name.strip():
        raise MspError("Name the organisation")
    if bool(admin_username) != bool(admin_email):
        raise MspError("Give both the administrator's username and email, or neither")
    client_id = await tenants.create(name.strip())
    await get_database()["tenants"].update_one({"_id": ObjectId(client_id)}, {"$set": {"managed_by": msp_id, "updated_at": utcnow()}})
    result: Dict[str, Any] = {"administrator": None, "temporary_password": None}
    if admin_username and admin_email:
        try:
            result["administrator"], result["temporary_password"] = await platform._new_admin(client_id, admin_username.strip(), admin_email.strip().lower())
        except platform.PlatformError as e:
            await get_database()["tenants"].delete_one({"_id": ObjectId(client_id)})
            raise MspError(str(e))
    await _record("msp.client_created", request, msp_id, client_id, {"name": name.strip()})
    result["organisation"] = (await platform.summaries([client_id]))[0]
    return result


async def release(client_id: str, request) -> None:
    """The client ends the MSP's access: its people can no longer work in it."""
    tenant = await tenants.get(client_id)
    msp_id = (tenant or {}).get("managed_by")
    if not msp_id:
        raise MspError("No service provider manages this organisation")
    await get_database()["tenants"].update_one({"_id": ObjectId(client_id)}, {"$unset": {"managed_by": ""}, "$set": {"updated_at": utcnow()}})
    await _record("msp.client_released", request, msp_id, client_id)


async def manager_name(tenant: Dict[str, Any]) -> Optional[str]:
    msp_id = tenant.get("managed_by")
    if not msp_id:
        return None
    found = await tenants.get(msp_id)
    return found["name"] if found else None


async def set_msp(tenant_id: str, value: bool) -> None:
    """Make an organisation an MSP, or stop (only when it manages no one)."""
    if not value and await client_ids(tenant_id):
        raise MspError("It still manages organisations: assign them elsewhere or release them first")
    tenant = await tenants.get(tenant_id)
    if value and tenant and tenant.get("managed_by"):
        raise MspError("An organisation managed by a service provider cannot be one itself")
    await get_database()["tenants"].update_one({"_id": ObjectId(tenant_id)}, {"$set": {"msp": value, "updated_at": utcnow()}})


async def set_manager(tenant_id: str, msp_id: Optional[str]) -> None:
    """Assign an organisation to an MSP, or to none."""
    if msp_id:
        if msp_id == tenant_id:
            raise MspError("An organisation cannot manage itself")
        if not is_msp(await tenants.get(msp_id)):
            raise MspError("That organisation is not a service provider")
        if is_msp(await tenants.get(tenant_id)):
            raise MspError("A service provider cannot be managed by another")
        await get_database()["tenants"].update_one({"_id": ObjectId(tenant_id)}, {"$set": {"managed_by": msp_id, "updated_at": utcnow()}})
    else:
        await get_database()["tenants"].update_one({"_id": ObjectId(tenant_id)}, {"$unset": {"managed_by": ""}, "$set": {"updated_at": utcnow()}})
