"""
Counting rules: a signature rule whose detection has an `aggregation` fires when enough
events matching its conditions arrive within a window, for the same value of a field
(`| count by user > 50 in 10m` in the gateway's rule language).

When an event matches the rule's conditions, the events of the same organisation stored
for correlation (the `events` collection, which keeps every analysed event) are counted
with the same conditions, as a MongoDB query, within the window before the event and for
the event's value of the field. The rule fires once the count passes the threshold, then
not again for that value until the window has passed (a cooldown): fifty downloads are one
alert, not one for every download after the fiftieth.
"""
import re
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from core.tenancy import current_tenant
from utils.time import utcnow

STATE = "identity_state"  # the cooldowns, shared with the identity detector (unique key, expiring)


def _value(event: Dict[str, Any], field: str) -> Any:
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _condition(op: str, expected: Any) -> Dict[str, Any]:
    """One comparison as a MongoDB condition; a missing field never matches, as in the signature detector."""
    present = {"$exists": True, "$ne": None}
    if op == "eq":
        return {"$eq": expected}
    if op == "ne":
        return {**present, "$ne": expected} if expected is not None else present
    if op == "in":
        return {"$in": list(expected)}
    if op == "not_in":
        return {"$nin": list(expected) + [None], "$exists": True}
    if op in ("gt", "gte", "lt", "lte"):
        return {f"${op}": expected}
    if op == "search":
        return {"$regex": expected}
    if op == "contains":
        return {"$regex": re.escape(str(expected))}
    if op == "starts_with":
        return {"$regex": "^" + re.escape(str(expected))}
    if op == "ends_with":
        return {"$regex": re.escape(str(expected)) + "$"}
    if op == "exists":
        return present
    raise ValueError(f"No counting for the comparison {op!r}")


def mongo_filter(detection: Dict[str, Any]) -> Dict[str, Any]:
    """The rule's conditions as a MongoDB filter on stored events."""
    clauses = []
    for field, comparisons in (detection.get("conditions") or {}).items():
        if not isinstance(comparisons, dict):
            comparisons = {"eq": comparisons}
        for op, expected in comparisons.items():
            clauses.append({field: _condition(op, expected)})
    if not clauses:
        return {}
    joined = "$or" if str(detection.get("condition_type", "AND")).upper() in ("OR", "ANY") else "$and"
    return {joined: clauses}


def _time(event: Dict[str, Any]) -> datetime:
    try:
        return datetime.fromisoformat(str(event.get("timestamp")))
    except ValueError:
        return utcnow().replace(tzinfo=None)


async def reached(rule: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    For an event that matches a counting rule's conditions: what the count came to, when it
    passes the threshold for the first time in the window; None otherwise.
    """
    aggregation = (rule.get("detection") or {}).get("aggregation") or {}
    window = timedelta(seconds=int(aggregation.get("window_seconds") or 0))
    threshold = int(aggregation.get("threshold") or 0)
    group_by = aggregation.get("group_by")
    group = _value(event, group_by) if group_by else None
    if not window or (group_by and group is None):
        return None
    at = _time(event)
    query: Dict[str, Any] = {**mongo_filter(rule["detection"]), "timestamp": {"$gte": (at - window).isoformat(), "$lte": at.isoformat()}}
    if group_by:
        query[group_by] = group
    if event.get("id"):
        query["id"] = {"$ne": event["id"]}  # this event is counted once, whether or not it is stored yet
    count = await get_database()["events"].count_documents(query) + 1
    passed = count >= threshold if aggregation.get("op") == "gte" else count > threshold
    if not passed:
        return None
    # Once per window for this group.
    state = get_database()[STATE]
    key = f"{current_tenant()}:count:{rule.get('_id') or rule.get('name')}:{group}"
    now = utcnow()
    await state.delete_one({"key": key, "until": {"$lte": now}})
    try:
        await state.insert_one({"key": key, "until": now + window})
    except DuplicateKeyError:
        return None
    return {"count": count, "group_by": group_by, "group": group, "window_seconds": int(window.total_seconds()), "threshold": threshold}
