"""An organisation's data in the engine, for the gateway (with the internal token)."""
import re

from fastapi import APIRouter

from core.database.connection import get_database
from core.tenancy import TENANT_SCOPED

router = APIRouter()


@router.delete("/{tenant_id}")
async def delete_tenant(tenant_id: str):
    """Delete everything the engine holds for an organisation: its events, alerts, rules and cooldowns."""
    database = get_database()
    raw = database._database if hasattr(database, "_database") else database
    deleted = 0
    for name in sorted(TENANT_SCOPED):
        deleted += (await raw[name].delete_many({"tenant_id": tenant_id})).deleted_count
    deleted += (await raw["rules"].delete_many({"tenant_id": tenant_id})).deleted_count
    deleted += (await raw["identity_state"].delete_many({"key": {"$regex": f"^{re.escape(tenant_id)}:"}})).deleted_count
    return {"deleted": deleted}
