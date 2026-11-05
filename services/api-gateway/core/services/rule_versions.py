"""
Versions of detection rules: every change to a rule (creating, editing, its status or tags)
keeps a numbered copy of the rule as it then was, with who changed it and when. An earlier
version can be restored, which makes a new version (history is never rewritten).
"""
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo import ReturnDocument

from core.database.connection import get_database
from core.tenancy import scoped
from utils.time import utcnow

COLLECTION = "rule_versions"
# What a version keeps: the rule's content, not its bookkeeping.
FIELDS = ("name", "description", "rule_type", "detection_source", "severity", "status", "tags", "logic", "notes", "test_cases")


def _versions():
    return scoped(get_database(), COLLECTION)


async def ensure_indexes() -> None:
    await get_database()[COLLECTION].create_index([("tenant_id", 1), ("rule_id", 1), ("version", -1)], unique=True)


async def record(rule_id: str, user_id: Optional[str], change: str) -> Optional[int]:
    """Keep the rule as it now is as its next version. Returns the version number."""
    if not ObjectId.is_valid(rule_id):
        return None
    rules = scoped(get_database(), "detection_rules")
    rule = await rules.find_one_and_update({"_id": ObjectId(rule_id)}, {"$inc": {"version": 1}}, return_document=ReturnDocument.AFTER)
    if not rule:
        return None
    version = rule["version"]
    await _versions().insert_one({
        "rule_id": rule_id, "version": version, "change": change, "changed_by": user_id, "at": utcnow(),
        "rule": {k: rule.get(k) for k in FIELDS},
    })
    return version


async def history(rule_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    return await _versions().find({"rule_id": rule_id}, {"_id": 0, "tenant_id": 0}).sort("version", -1).limit(limit).to_list(limit)


async def get(rule_id: str, version: int) -> Optional[Dict[str, Any]]:
    return await _versions().find_one({"rule_id": rule_id, "version": version}, {"_id": 0, "tenant_id": 0})
