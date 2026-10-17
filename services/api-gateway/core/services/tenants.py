"""Tenants: the organisations whose data UTDRS keeps apart (see core.tenancy)."""
import re
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from config import settings
from core.database.connection import get_database
from core.tenancy import FIELD, TENANT_SCOPED
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "tenants"


def _tenants():
    # Tenants themselves are platform data: not scoped.
    return get_database()[COLLECTION]


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "organisation"


async def create(name: str) -> str:
    """A new tenant. Its slug is made unique by adding a number when needed."""
    base, n = _slug(name), 1
    slug = base
    while await _tenants().find_one({"slug": slug}):
        n += 1
        slug = f"{base}-{n}"
    now = utcnow()
    result = await _tenants().insert_one({"name": name, "slug": slug, "status": "active", "created_at": now, "updated_at": now})
    logger.info(f"Created tenant {slug}")
    return str(result.inserted_id)


async def get(tenant_id: str) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(tenant_id):
        return None
    return await _tenants().find_one({"_id": ObjectId(tenant_id)})


async def get_by_slug(slug: str) -> Optional[Dict[str, Any]]:
    return await _tenants().find_one({"slug": slug})


async def rename(tenant_id: str, name: str) -> Optional[Dict[str, Any]]:
    from pymongo import ReturnDocument

    return await _tenants().find_one_and_update(
        {"_id": ObjectId(tenant_id)}, {"$set": {"name": name, "updated_at": utcnow()}}, return_document=ReturnDocument.AFTER
    )


async def all_ids() -> List[str]:
    return [str(t["_id"]) async for t in _tenants().find({"status": "active"}, {"_id": 1})]


async def default_id() -> str:
    tenant = await get_by_slug(settings.DEFAULT_TENANT_SLUG)
    if not tenant:
        raise RuntimeError("The default tenant does not exist; the gateway creates it at start-up")
    return str(tenant["_id"])


async def ensure_default() -> str:
    """
    The default tenant: where a single organisation's deployment keeps its data, where
    self-registration joins in "join" mode, and where data from before tenancy goes.
    """
    # Slugs are unique, so even two processes starting at once make only one tenant.
    await _tenants().create_index("slug", unique=True)
    tenant = await get_by_slug(settings.DEFAULT_TENANT_SLUG)
    if tenant:
        return str(tenant["_id"])
    now = utcnow()
    try:
        result = await _tenants().insert_one(
            {"name": settings.DEFAULT_TENANT_NAME, "slug": settings.DEFAULT_TENANT_SLUG, "status": "active", "created_at": now, "updated_at": now}
        )
    except DuplicateKeyError:
        return str((await get_by_slug(settings.DEFAULT_TENANT_SLUG))["_id"])
    logger.info(f"Created the default tenant ({settings.DEFAULT_TENANT_SLUG})")
    return str(result.inserted_id)


async def adopt_untenanted(tenant_id: str) -> None:
    """Give data from before tenancy to `tenant_id`. Runs at start-up; does nothing once done."""
    database = get_database()
    for name in sorted(TENANT_SCOPED):
        result = await database[name].update_many({FIELD: {"$exists": False}}, {"$set": {FIELD: tenant_id}})
        if result.modified_count:
            logger.info(f"Moved {result.modified_count} {name} documents into the default tenant")
    # Singleton documents keyed by _id before tenancy are keyed by kind within a tenant now.
    await database["audit_log_head"].update_many({"_id": "audit_head", "kind": {"$exists": False}}, {"$set": {"kind": "head"}})
    await database["gateway_state"].update_many({"_id": "rule_sync", "kind": {"$exists": False}}, {"$set": {"kind": "rule_sync"}})
