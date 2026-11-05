"""
SCIM 2.0 (RFC 7643, 7644): an organisation's identity provider (Microsoft Entra ID, Okta,
...) creates, updates and deactivates its people's UTDRS accounts itself.

Each organisation has at most one SCIM token, made by an administrator, shown once and
kept only as a hash. The identity provider sends it as a bearer token; it names the
organisation. Accounts it creates are analysts with confirmed addresses, who sign in with
single sign-on or a passkey; SCIM never changes anyone's role, and never deactivates an
organisation's last active administrator. Deactivating someone ends their sessions.
"""
import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional, Tuple

from bson import ObjectId

from core.database.connection import get_database
from utils.time import utcnow

PREFIX = "utdrs_scim_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def ensure_indexes() -> None:
    await get_database()["tenants"].create_index("scim.token_hash", unique=True, sparse=True)


async def new_token(tenant_id: str, actor: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """A new token for the organisation, replacing any it had. Returns it (shown once) and what is kept."""
    token = f"{PREFIX}{secrets.token_urlsafe(32)}"
    kept = {"token_hash": _hash(token), "created_at": utcnow(), "created_by": actor, "last_used_at": None}
    await get_database()["tenants"].update_one({"_id": ObjectId(tenant_id)}, {"$set": {"scim": kept}})
    return token, kept


async def revoke(tenant_id: str) -> bool:
    result = await get_database()["tenants"].update_one({"_id": ObjectId(tenant_id), "scim": {"$exists": True}}, {"$unset": {"scim": ""}})
    return bool(result.modified_count)


async def status(tenant: Dict[str, Any]) -> Dict[str, Any]:
    kept = tenant.get("scim") or {}
    return {"enabled": bool(kept), "created_at": kept.get("created_at"), "last_used_at": kept.get("last_used_at")}


async def tenant_for(token: str) -> Optional[str]:
    """The organisation a SCIM token belongs to, or None."""
    if not token.startswith(PREFIX):
        return None
    found = await get_database()["tenants"].find_one({"scim.token_hash": _hash(token)}, {"scim": 1})
    if not found or not hmac.compare_digest(found["scim"]["token_hash"], _hash(token)):
        return None
    await get_database()["tenants"].update_one({"_id": found["_id"]}, {"$set": {"scim.last_used_at": utcnow()}})
    return str(found["_id"])
