"""
The platform console: what operators (core/services/operators.py), who run a UTDRS
deployment apart from every organisation, do across organisations.

Operators see every organisation and its numbers, create organisations with their first
administrator, add an administrator to an organisation that is locked out, suspend and
reactivate organisations, delete them with all their data, and set up service providers.
Each action is recorded in the platform's audit log and, when
it concerns an organisation, in that organisation's own, so it can see what was done to it.
"""
import re
import secrets
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import gridfs
from bson import ObjectId

from core.database.connection import get_database
from core.database.repositories.user_repository import UserRepository
from core.models.user import ADMIN, UserCreate
from core.services import audit, tenants
from core.tenancy import PLATFORM, TENANT_SCOPED, tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

# Collections that hold an organisation's data but are not scoped through core.tenancy.
ALSO_BY_TENANT = ["sso_configs", "account_tokens", "sso_logins", "metrics_http"]


class PlatformError(ValueError):
    """The platform action cannot be done; the message says why, for people."""


def _actor(admin) -> Dict[str, Any]:
    return {"type": "operator", "id": admin.id, "name": admin.username}


async def _record(action: str, request, admin, tenant_id: Optional[str], details: Optional[Dict[str, Any]] = None) -> None:
    """In the platform's log, and in the organisation's (it should see what was done to it)."""
    target = {"type": "tenant", "id": tenant_id} if tenant_id else None
    await audit.record(action, request, actor=_actor(admin), target=target, details=details, tenant_id=PLATFORM)
    if tenant_id:
        await audit.record(action, request, actor=_actor(admin), target=target, details=details, tenant_id=tenant_id)


async def summaries(ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Every organisation (or those named), with what an operator or MSP needs to see at a glance."""
    database = get_database()
    week_ago = utcnow() - timedelta(days=7)
    only: Dict[str, Any] = {"tenant_id": {"$in": ids}} if ids is not None else {}

    async def grouped(collection: str, match: Dict[str, Any]) -> Dict[str, int]:
        rows = await (await database[collection].aggregate([{"$match": {**match, **only}}, {"$group": {"_id": "$tenant_id", "n": {"$sum": 1}}}])).to_list(None)
        return {row["_id"]: row["n"] for row in rows}

    people = await grouped("users", {"active": True})
    admins = await grouped("users", {"active": True, "role": ADMIN})
    events = await grouped("events", {"created_at": {"$gte": week_ago}})
    open_alerts = await grouped("alerts", {"status": {"$nin": ["resolved", "closed", "false_positive", "suppressed"]}})
    urgent_alerts = await grouped("alerts", {"status": {"$nin": ["resolved", "closed", "false_positive", "suppressed"]}, "severity": {"$in": ["critical", "high"]}})
    connectors = await grouped("connections", {})
    last_sign_in = {row["_id"]: row["at"] for row in await (await database["users"].aggregate(
        [*([{"$match": only}] if only else []), {"$group": {"_id": "$tenant_id", "at": {"$max": "$lastLogin"}}}])).to_list(None)}
    default = await tenants.default_id()
    all_tenants = await database["tenants"].find({} if ids is None else {"_id": {"$in": [ObjectId(i) for i in ids if ObjectId.is_valid(i)]}}).sort("created_at", 1).to_list(None)
    names = {str(t["_id"]): t["name"] async for t in database["tenants"].find({"msp": True}, {"name": 1})}
    result = []
    for tenant in all_tenants:
        tenant_id = str(tenant["_id"])
        result.append({
            "id": tenant_id, "name": tenant["name"], "slug": tenant.get("slug"), "status": tenant.get("status", "active"),
            "created_at": tenant.get("created_at"), "default": tenant_id == default,
            "people": people.get(tenant_id, 0), "administrators": admins.get(tenant_id, 0), "events_last_week": events.get(tenant_id, 0),
            "open_alerts": open_alerts.get(tenant_id, 0), "connectors": connectors.get(tenant_id, 0), "last_sign_in": last_sign_in.get(tenant_id),
            "mfa_required": bool((tenant.get("security") or {}).get("require_mfa")),
            "urgent_alerts": urgent_alerts.get(tenant_id, 0), "msp": bool(tenant.get("msp")),
            "managed_by": tenant.get("managed_by"), "managed_by_name": names.get(tenant.get("managed_by") or ""),
        })
    return result


async def detail(tenant_id: str) -> Dict[str, Any]:
    found = next(iter(await summaries([tenant_id])), None) if ObjectId.is_valid(tenant_id) else None
    if not found:
        raise LookupError("Organisation not found")
    users = await get_database()["users"].find(
        {"tenant_id": tenant_id}, {"username": 1, "email": 1, "role": 1, "active": 1, "lastLogin": 1, "mfa.enabled": 1},
    ).sort("username", 1).to_list(1000)
    found["users"] = [{"id": str(u["_id"]), "username": u["username"], "email": u.get("email"), "role": u.get("role"), "active": u.get("active", True),
                       "last_sign_in": u.get("lastLogin"),
                       "mfa": bool((u.get("mfa") or {}).get("enabled"))} for u in users]
    return found


def _temporary_password() -> str:
    return secrets.token_urlsafe(12)


async def _new_admin(tenant_id: str, username: str, email: str) -> Tuple[Dict[str, Any], str]:
    repo = UserRepository()
    if await repo.find_by_username(username):
        raise PlatformError(f"The username {username} is taken")
    if await repo.find_by_email(email):
        raise PlatformError(f"{email} already has an account")
    password = _temporary_password()
    try:
        account = UserCreate(username=username, email=email, password=password, role=ADMIN, active=True)
    except ValueError as e:
        raise PlatformError(f"Not valid: {e}")
    with tenant_context(tenant_id):
        user_id = await repo.create_user(account, email_verified=False, created_by_platform=True)
    return {"id": user_id, "username": username, "email": email}, password


async def create_organisation(name: str, admin_username: str, admin_email: str, request, admin) -> Dict[str, Any]:
    """A new organisation and its first administrator, with a temporary password shown once."""
    if not name.strip():
        raise PlatformError("Name the organisation")
    tenant_id = await tenants.create(name.strip())
    try:
        user, password = await _new_admin(tenant_id, admin_username.strip(), admin_email.strip().lower())
    except PlatformError:
        await get_database()["tenants"].delete_one({"_id": ObjectId(tenant_id)})
        raise
    await _record("platform.organisation_created", request, admin, tenant_id, {"name": name, "administrator": user["username"]})
    return {"tenant": await detail(tenant_id), "administrator": user, "temporary_password": password}


async def add_administrator(tenant_id: str, username: str, email: str, request, admin) -> Dict[str, Any]:
    """Another administrator for an organisation, such as one whose administrators are locked out."""
    if not await tenants.get(tenant_id):
        raise LookupError("Organisation not found")
    user, password = await _new_admin(tenant_id, username.strip(), email.strip().lower())
    await _record("platform.administrator_added", request, admin, tenant_id, {"administrator": user["username"]})
    return {"administrator": user, "temporary_password": password}


async def set_status(tenant_id: str, suspended: bool, request, admin) -> Dict[str, Any]:
    tenant = await tenants.get(tenant_id)
    if not tenant:
        raise LookupError("Organisation not found")
    await get_database()["tenants"].update_one({"_id": ObjectId(tenant_id)}, {"$set": {"status": "suspended" if suspended else "active", "updated_at": utcnow()}})
    tenants.forget_suspension(tenant_id)
    if suspended:
        # Everyone in it is signed out at once.
        await get_database()["sessions"].update_many({"tenant_id": tenant_id, "ended_at": None},
                                                    {"$set": {"ended_at": utcnow(), "end_reason": "This organisation has been suspended"}})
    await _record("platform.organisation_suspended" if suspended else "platform.organisation_reactivated", request, admin, tenant_id)
    return await detail(tenant_id)


async def delete_organisation(tenant_id: str, confirm_name: str, request, admin) -> Dict[str, int]:
    """Delete an organisation and everything it holds, here and in the core engine. Cannot be undone."""
    tenant = await tenants.get(tenant_id)
    if not tenant:
        raise LookupError("Organisation not found")
    if confirm_name != tenant["name"]:
        raise PlatformError("Type the organisation's name exactly to confirm")
    if tenant_id == await tenants.default_id():
        raise PlatformError("The default organisation (where people who register without one go) cannot be deleted")
    database = get_database()
    deleted: Dict[str, int] = {}
    for name in sorted(set(TENANT_SCOPED) | set(ALSO_BY_TENANT)):
        removed = (await database[name].delete_many({"tenant_id": tenant_id})).deleted_count
        if removed:
            deleted[name] = removed
    bucket = gridfs.AsyncGridFSBucket(database, bucket_name="case_files")
    files = 0
    async for found in database["case_files.files"].find({"metadata.tenant_id": tenant_id}, {"_id": 1}):
        await bucket.delete(found["_id"])
        files += 1
    if files:
        deleted["case_files"] = files
    await database["identity_state"].delete_many({"key": {"$regex": f"^{re.escape(tenant_id)}:"}})
    await database["tenants"].delete_one({"_id": ObjectId(tenant_id)})
    tenants.forget_suspension(tenant_id)
    from core.services import core_engine_client

    engine = core_engine_client.get_core_engine_client()
    if engine is not None:
        try:
            deleted["engine"] = await engine.delete_tenant(tenant_id)
        except core_engine_client.CoreEngineError as e:
            logger.warning(f"The core engine could not delete organisation {tenant_id}'s data: {e}; its copies expire on their own")
    await audit.record("platform.organisation_deleted", request, actor=_actor(admin), target={"type": "tenant", "id": tenant_id, "name": tenant["name"]},
                       details={"deleted": deleted}, tenant_id=PLATFORM)
    return deleted


async def set_msp(tenant_id: str, msp: Optional[bool], managed_by: Optional[str], request, admin) -> Dict[str, Any]:
    """Make an organisation a service provider (or not), or assign it to one (managed_by "" for none)."""
    from core.services import msp as msp_service

    if not await tenants.get(tenant_id):
        raise LookupError("Organisation not found")
    try:
        if msp is not None:
            await msp_service.set_msp(tenant_id, msp)
            await _record("platform.msp_granted" if msp else "platform.msp_removed", request, admin, tenant_id)
        if managed_by is not None:
            await msp_service.set_manager(tenant_id, managed_by or None)
            await _record("platform.manager_changed", request, admin, tenant_id, {"managed_by": managed_by or None})
    except msp_service.MspError as e:
        raise PlatformError(str(e))
    return await detail(tenant_id)
