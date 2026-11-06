"""
Custom roles: an organisation's own roles, each a chosen set of permissions.

A permission is an area and an access, as API keys have them: `alerts:read` to see alerts,
`alerts:write` to change them. A custom role can grant any of what an analyst can do, area by
area, and nothing more: administering the organisation (its people, connectors, keys, rules,
playbooks, simulations and settings) stays with administrators. Built-in roles are unchanged:
administrator, analyst (every permission here) and read-only (every :read).

People with a custom role have the role "custom" and its id. Their permissions are checked by
the same router-wide check as API keys' scopes (utils/security.require_scope).
"""
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from core.tenancy import scoped
from utils.time import utcnow

COLLECTION = "roles"
CUSTOM = "custom"

# Each area, what seeing it and changing it mean; areas without "write" can only be seen
# (changing them is for administrators).
AREAS: Dict[str, Dict[str, str]] = {
    "alerts": {"label": "Alerts", "read": "See alerts", "write": "Triage alerts: status, owner, notes, tags"},
    "cases": {"label": "Cases", "read": "See cases and their files", "write": "Work cases: status, notes, files, owners"},
    "events": {"label": "Events", "read": "See events", "write": "Send events and test events"},
    "assets": {"label": "Assets", "read": "See assets", "write": "Change assets"},
    "response": {"label": "Response", "read": "See response actions", "write": "Request, approve and reject response actions"},
    "reports": {"label": "Reports", "read": "See reports", "write": "Make reports"},
    "tuning": {"label": "Tuning", "read": "See verdicts and suppressions", "write": "Give verdicts, suppress and allow"},
    "email": {"label": "Email checks", "read": "See checked emails", "write": "Check emails for phishing"},
    "rules": {"label": "Detection rules", "read": "See detection rules"},
    "playbooks": {"label": "Playbooks", "read": "See playbooks"},
    "simulations": {"label": "Simulations", "read": "See simulations"},
}
PERMISSIONS: List[str] = [f"{area}:{access}" for area, info in AREAS.items() for access in ("read", "write") if access in info]
ANALYST_PERMISSIONS = list(PERMISSIONS)
VIEWER_PERMISSIONS = [p for p in PERMISSIONS if p.endswith(":read")]


class RoleError(ValueError):
    """The role cannot be saved or deleted; the message says why, for people."""


def _roles():
    return scoped(get_database(), COLLECTION)


async def ensure_indexes() -> None:
    await get_database()[COLLECTION].create_index([("tenant_id", 1), ("name", 1)], unique=True)


def _clean(permissions: List[str]) -> List[str]:
    unknown = sorted(set(permissions) - set(PERMISSIONS))
    if unknown:
        raise RoleError(f"Not permissions a role can have: {', '.join(unknown)}")
    chosen = set(permissions)
    # Changing an area means seeing it too.
    chosen |= {p.replace(":write", ":read") for p in chosen if p.endswith(":write")}
    return [p for p in PERMISSIONS if p in chosen]


def public(doc: Dict[str, Any], people: int = 0) -> Dict[str, Any]:
    return {"id": str(doc["_id"]), "name": doc["name"], "description": doc.get("description") or "", "permissions": doc.get("permissions") or [],
            "people": people, "created_at": doc.get("created_at"), "updated_at": doc.get("updated_at")}


async def _counts() -> Dict[str, int]:
    rows = await (await scoped(get_database(), "users").aggregate([{"$match": {"role": CUSTOM}}, {"$group": {"_id": "$custom_role_id", "n": {"$sum": 1}}}])).to_list(None)
    return {row["_id"]: row["n"] for row in rows if row["_id"]}


async def list_roles() -> List[Dict[str, Any]]:
    counts = await _counts()
    return [public(doc, counts.get(str(doc["_id"]), 0)) async for doc in _roles().find().sort("name", 1)]


async def get(role_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not role_id or not ObjectId.is_valid(role_id):
        return None
    return await _roles().find_one({"_id": ObjectId(role_id)})


async def permissions_of(role_id: Optional[str]) -> List[str]:
    """A custom role's permissions; none if the role is gone."""
    role = await get(role_id)
    return list(role.get("permissions") or []) if role else []


async def create(name: str, description: str, permissions: List[str], created_by: Dict[str, Any]) -> Dict[str, Any]:
    now = utcnow()
    doc = {"name": name.strip(), "description": description.strip(), "permissions": _clean(permissions), "created_at": now, "updated_at": now,
           "created_by": created_by}
    if not doc["name"]:
        raise RoleError("Name the role")
    try:
        result = await _roles().insert_one(doc)
    except DuplicateKeyError:
        raise RoleError(f"There is already a role called {doc['name']}")
    return public({**doc, "_id": result.inserted_id})


async def update(role_id: str, name: Optional[str], description: Optional[str], permissions: Optional[List[str]]) -> Dict[str, Any]:
    role = await get(role_id)
    if not role:
        raise LookupError("Role not found")
    changes: Dict[str, Any] = {"updated_at": utcnow()}
    if name is not None:
        if not name.strip():
            raise RoleError("Name the role")
        changes["name"] = name.strip()
    if description is not None:
        changes["description"] = description.strip()
    if permissions is not None:
        changes["permissions"] = _clean(permissions)
    try:
        await _roles().update_one({"_id": role["_id"]}, {"$set": changes})
    except DuplicateKeyError:
        raise RoleError(f"There is already a role called {changes.get('name')}")
    return public({**role, **changes}, (await _counts()).get(role_id, 0))


async def delete(role_id: str) -> None:
    role = await get(role_id)
    if not role:
        raise LookupError("Role not found")
    people = (await _counts()).get(role_id, 0)
    if people:
        raise RoleError(f"{people} {'person has' if people == 1 else 'people have'} this role: give them another first")
    groups = await scoped(get_database(), "scim_groups").count_documents({"custom_role_id": role_id})
    if groups:
        raise RoleError(f"{groups} SCIM {'group gives' if groups == 1 else 'groups give'} this role: change {'it' if groups == 1 else 'them'} first")
    await _roles().delete_one({"_id": role["_id"]})


async def check_assignable(role: str, custom_role_id: Optional[str]) -> Optional[str]:
    """The custom role id to store with `role` (None for built-in roles); refuses a custom role that does not exist here."""
    if role != CUSTOM:
        return None
    if not await get(custom_role_id):
        raise RoleError("Choose one of your organisation's custom roles")
    return custom_role_id


async def may(user: Dict[str, Any], permission: str) -> bool:
    """Whether a person may do this (for choosing whom to notify)."""
    role = user.get("role")
    if role == "admin":
        return True
    if role == "viewer":
        return permission.endswith(":read")
    if role == CUSTOM:
        return permission in await permissions_of(user.get("custom_role_id"))
    return True  # analysts
