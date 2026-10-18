"""
API keys: credentials for scripts, agents and integrations, instead of a person's password.

A key looks like `utdrs_<prefix>_<secret>`. Only its SHA-256 is stored (a key is long
and random, so a slow password hash adds nothing); the prefix identifies it in lists and
logs. A key carries scopes, `<area>:read` or `<area>:write`, checked on every request
(see utils.security.require_scope), and can never do what only administrators can.
"""
import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId

from core.database.connection import get_database
from core.tenancy import scoped
from utils.time import utcnow

PREFIX = "utdrs_"
COLLECTION = "api_keys"
AREAS = ["alerts", "cases", "events", "assets", "rules", "simulations", "response", "playbooks"]
SCOPES = [f"{area}:{access}" for area in AREAS for access in ("read", "write")]
# last_used_at is updated at most this often, so busy keys do not write on every request.
LAST_USED_RESOLUTION = timedelta(minutes=5)


def _keys():
    """The current organisation's keys."""
    return scoped(get_database(), COLLECTION)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


async def ensure_indexes() -> None:
    await get_database()[COLLECTION].create_index("prefix", unique=True)


async def create(name: str, scopes: List[str], created_by: Dict[str, Any], expires_in_days: Optional[int]) -> Tuple[Dict[str, Any], str]:
    """Create a key. Returns its record and the key itself, which is not stored and cannot be shown again."""
    prefix = secrets.token_hex(4)
    key = f"{PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    now = utcnow()
    doc = {
        "name": name,
        "prefix": prefix,
        "hash": _hash(key),
        "scopes": sorted(set(scopes)),
        "created_by": created_by,
        "created_at": now,
        "expires_at": now + timedelta(days=expires_in_days) if expires_in_days else None,
        "last_used_at": None,
        "revoked_at": None,
    }
    result = await _keys().insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc, key


async def authenticate(key: str) -> Optional[Dict[str, Any]]:
    """The key's record when the key is valid, unrevoked and unexpired; otherwise None."""
    parts = key.split("_")
    if not key.startswith(PREFIX) or len(parts) < 3:
        return None
    # Across organisations: the key itself says which organisation it belongs to.
    doc = await get_database()[COLLECTION].find_one({"prefix": parts[1]})
    if not doc or not hmac.compare_digest(doc["hash"], _hash(key)):
        return None
    now = utcnow()
    if doc.get("revoked_at") or (doc.get("expires_at") and doc["expires_at"] <= now):
        return None
    if not doc.get("last_used_at") or now - doc["last_used_at"] > LAST_USED_RESOLUTION:
        await get_database()[COLLECTION].update_one({"_id": doc["_id"]}, {"$set": {"last_used_at": now}})
    return doc


async def list_keys() -> List[Dict[str, Any]]:
    return await _keys().find({}, {"hash": 0}).sort("_id", -1).to_list(None)


async def revoke(key_id: str) -> Optional[Dict[str, Any]]:
    """Revoke a key; it stops working at once. Returns the key as it was, or None if unknown."""
    if not ObjectId.is_valid(key_id):
        return None
    return await _keys().find_one_and_update(
        {"_id": ObjectId(key_id), "revoked_at": None},
        {"$set": {"revoked_at": utcnow()}},
        projection={"hash": 0},
    )
