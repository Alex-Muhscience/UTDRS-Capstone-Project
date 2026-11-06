"""
SCIM groups: the identity provider manages groups and their members, and an organisation's
administrators decide what each group means in UTDRS: a role (administrator, analyst,
read-only, or one of the organisation's custom roles), or nothing.

Someone in one or more groups that have a role gets the most powerful of them: administrator,
then analyst, then custom roles (by the group's name), then read-only. Someone whose role came
from groups (`role_source: scim_group`) and who is no longer in any such group becomes
read-only; people whose role was set by hand and who are in no such group keep theirs. Roles
change at once, as membership or a group's role changes, and never leave an organisation
without an active administrator. Each change is in the audit log.
"""
from typing import Any, Dict, Iterable, List, Optional

from bson import ObjectId

from core.database.connection import get_database
from core.services import audit, roles
from core.tenancy import scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

ACTOR = {"type": "scim", "name": "identity provider (SCIM)"}
ROLES = ("admin", "analyst", "viewer", "custom")
PRECEDENCE = {"admin": 0, "analyst": 1, "custom": 2, "viewer": 3}
FALLBACK = "viewer"


class GroupError(ValueError):
    """The group cannot be changed this way; the message says why."""


def _groups():
    return scoped(get_database(), "scim_groups")


def _users():
    return scoped(get_database(), "users")


async def ensure_indexes() -> None:
    await get_database()["scim_groups"].create_index([("tenant_id", 1), ("display_name", 1)])
    await get_database()["scim_groups"].create_index([("tenant_id", 1), ("members", 1)])


async def get(group_id: str) -> Optional[Dict[str, Any]]:
    return await _groups().find_one({"_id": ObjectId(group_id)}) if ObjectId.is_valid(group_id) else None


async def find(query: Dict[str, Any], skip: int, limit: int) -> List[Dict[str, Any]]:
    return await _groups().find(query).sort("_id", 1).skip(skip).limit(limit).to_list(limit)


async def count(query: Dict[str, Any]) -> int:
    return await _groups().count_documents(query)


async def _known(member_ids: Iterable[str]) -> List[str]:
    """Only people of this organisation can be members; others (not provisioned yet) are left out."""
    wanted = {m for m in member_ids if ObjectId.is_valid(m)}
    if not wanted:
        return []
    found = await _users().find({"_id": {"$in": [ObjectId(m) for m in wanted]}}, {"_id": 1}).to_list(None)
    return sorted(str(u["_id"]) for u in found)


async def create(display_name: str, external_id: Optional[str], members: List[str], request) -> Dict[str, Any]:
    if not display_name.strip():
        raise GroupError("displayName is needed")
    if await _groups().find_one({"display_name": display_name.strip()}):
        raise GroupError(f"A group called {display_name} exists")
    now = utcnow()
    doc = {"display_name": display_name.strip(), "external_id": external_id, "members": await _known(members), "role": None,
           "custom_role_id": None, "created_at": now, "updated_at": now}
    result = await _groups().insert_one(doc)
    doc["_id"] = result.inserted_id
    await audit.record("scim.group_created", request, actor=ACTOR, target={"type": "scim_group", "id": str(doc["_id"]), "name": doc["display_name"]})
    return doc


async def update(group: Dict[str, Any], request, display_name: Optional[str] = None, external_id: Optional[str] = None,
                 members: Optional[List[str]] = None, add: Iterable[str] = (), remove: Iterable[str] = ()) -> Dict[str, Any]:
    """Change a group; the roles of everyone whose membership changed follow."""
    before = set(group.get("members") or [])
    after = set(await _known(members)) if members is not None else set(before)
    after |= set(await _known(add))
    after -= set(remove)
    fields: Dict[str, Any] = {"members": sorted(after), "updated_at": utcnow()}
    if display_name is not None and display_name.strip():
        fields["display_name"] = display_name.strip()
    if external_id is not None:
        fields["external_id"] = external_id
    await _groups().update_one({"_id": group["_id"]}, {"$set": fields})
    changed = before ^ after
    if changed:
        await audit.record("scim.group_members_changed", request, actor=ACTOR,
                           target={"type": "scim_group", "id": str(group["_id"]), "name": fields.get("display_name", group["display_name"])},
                           details={"added": sorted(after - before), "removed": sorted(before - after)})
        await sync(changed, request)
    return {**group, **fields}


async def delete(group: Dict[str, Any], request) -> None:
    await _groups().delete_one({"_id": group["_id"]})
    await audit.record("scim.group_deleted", request, actor=ACTOR, target={"type": "scim_group", "id": str(group["_id"]), "name": group["display_name"]})
    await sync(group.get("members") or [], request)


async def set_role(group_id: str, role: Optional[str], custom_role_id: Optional[str], request) -> Dict[str, Any]:
    """An administrator decides what a group means in UTDRS (None: nothing)."""
    group = await get(group_id)
    if not group:
        raise LookupError("Group not found")
    if role is not None and role not in ROLES:
        raise GroupError("Choose administrator, analyst, read-only, a custom role, or none")
    try:
        stored_custom = await roles.check_assignable(role, custom_role_id) if role else None
    except roles.RoleError as e:
        raise GroupError(str(e))
    await _groups().update_one({"_id": group["_id"]}, {"$set": {"role": role, "custom_role_id": stored_custom, "updated_at": utcnow()}})
    await audit.record("scim.group_role_set", request, target={"type": "scim_group", "id": group_id, "name": group["display_name"]},
                       changes={"role": [group.get("role"), role], "custom_role_id": [group.get("custom_role_id"), stored_custom]})
    await sync(group.get("members") or [], request)
    return {**group, "role": role, "custom_role_id": stored_custom}


def _rank(group: Dict[str, Any]) -> tuple:
    return (PRECEDENCE.get(group["role"], 9), group["display_name"].lower())


async def role_from_groups(user_id: str) -> Optional[Dict[str, Any]]:
    """The role a person's groups give them, or None when no group of theirs has one."""
    mapped = await _groups().find({"members": user_id, "role": {"$ne": None}}).to_list(None)
    if not mapped:
        return None
    best = min(mapped, key=_rank)
    return {"role": best["role"], "custom_role_id": best.get("custom_role_id"), "group": best["display_name"]}


async def _would_lose_last_admin(user: Dict[str, Any], new_role: str) -> bool:
    if user.get("role") != "admin" or new_role == "admin" or not user.get("active", True):
        return False
    return not await _users().count_documents({"role": "admin", "active": True, "_id": {"$ne": user["_id"]}})


async def sync(user_ids: Iterable[str], request=None) -> None:
    """Bring these people's roles in line with their groups."""
    for user_id in {u for u in user_ids if ObjectId.is_valid(u)}:
        user = await _users().find_one({"_id": ObjectId(user_id)})
        if not user:
            continue
        given = await role_from_groups(user_id)
        if given:
            target = {"role": given["role"], "custom_role_id": given["custom_role_id"] if given["role"] == "custom" else None, "role_source": "scim_group"}
            reason = f"group {given['group']}"
        elif user.get("role_source") == "scim_group":
            target = {"role": FALLBACK, "custom_role_id": None, "role_source": "scim_group"}
            reason = "no longer in a group with a role"
        else:
            continue
        if user.get("role") == target["role"] and user.get("custom_role_id") == target["custom_role_id"] and user.get("role_source") == "scim_group":
            continue
        if await _would_lose_last_admin(user, target["role"]):
            await audit.record("scim.role_change_skipped", request, actor=ACTOR, outcome="denied",
                               target={"type": "user", "id": user_id, "name": user["username"]},
                               details={"reason": "the organisation's last active administrator", "would_be": target["role"]})
            continue
        await _users().update_one({"_id": user["_id"]}, {"$set": {**target, "updatedAt": utcnow()}})
        await audit.record("scim.role_changed", request, actor=ACTOR, target={"type": "user", "id": user_id, "name": user["username"]},
                           changes={"role": [user.get("role"), target["role"]]}, details={"because": reason})


async def summaries() -> List[Dict[str, Any]]:
    """For administrators: each group, its size, and what it means in UTDRS."""
    names = {r["id"]: r["name"] for r in await roles.list_roles()}
    return [{"id": str(g["_id"]), "display_name": g["display_name"], "members": len(g.get("members") or []), "role": g.get("role"),
             "custom_role_id": g.get("custom_role_id"), "custom_role_name": names.get(g.get("custom_role_id") or ""),
             "updated_at": g.get("updated_at")} async for g in _groups().find().sort("display_name", 1)]
