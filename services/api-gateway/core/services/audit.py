"""
The audit log: who did what, when, from where, to what.

Entries are written for sign-ins, account changes, rule, alert and asset changes, and
API keys. Each entry holds the hash of the one before it, so an edited, inserted or
deleted entry breaks the chain, which verify() finds. Entries are numbered: a missing
number shows an entry was removed, or a write failed part-way.
"""
import asyncio
import hashlib
import json
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Request
from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from core.tenancy import PLATFORM, current_tenant_or_none, scoped, tenant_context
from utils.client_address import client_address
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "audit_log"
# Each organisation has its own numbered chain, so its administrators can read and check
# it without seeing anyone else's. The head holds the chain's last number and hash.
HEAD = {"kind": "head"}
GENESIS = "0" * 64
MAX_ATTEMPTS = 50
# An entry claims its number a moment before it is stored, so for a few seconds a number
# can be missing because its entry is still being written. Gaps that recent are not
# reported as tampering.
WRITE_GRACE_SECONDS = 10
# Writes from one process take turns, so they never compete for the next number; other
# processes (gunicorn workers, replicas) are handled by retrying.
_write_lock = asyncio.Lock()


def _canonical(entry: Dict[str, Any]) -> bytes:
    def default(value):
        if isinstance(value, datetime):
            # To the millisecond, in UTC: what MongoDB stores and gives back.
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            value = value.astimezone(timezone.utc)
            return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
        return str(value)

    # The tenant is not hashed: it is where the chain lives, not part of what happened.
    body = {k: v for k, v in entry.items() if k not in ("_id", "hash", "tenant_id")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=default).encode("utf-8")


def _digest(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


async def ensure_indexes() -> None:
    collection = get_database()[COLLECTION]
    # Numbers are unique within an organisation's chain (before tenancy, across the log).
    if "seq_1" in await collection.index_information():
        await _drop_index(collection, "seq_1")
    await collection.create_index([("tenant_id", 1), ("seq", 1)], unique=True)
    await collection.create_index([("tenant_id", 1), ("at", -1)])
    await collection.create_index([("tenant_id", 1), ("action", 1), ("at", -1)])
    await collection.create_index([("tenant_id", 1), ("target.type", 1), ("target.id", 1)])
    await get_database()[COLLECTION + "_head"].create_index([("tenant_id", 1), ("kind", 1)], unique=True)


async def _drop_index(collection, name: str) -> None:
    from pymongo.errors import OperationFailure

    try:
        await collection.drop_index(name)
    except OperationFailure as e:
        if e.code != 27:  # IndexNotFound: already dropped
            raise


def _log():
    return scoped(get_database(), COLLECTION)


def _head():
    return scoped(get_database(), COLLECTION + "_head")


def actor_of(request: Optional[Request]) -> Dict[str, Any]:
    principal = getattr(getattr(request, "state", None), "principal", None) if request else None
    return dict(principal) if principal else {"type": "anonymous"}


async def record(
    action: str,
    request: Optional[Request] = None,
    *,
    target: Optional[Dict[str, Any]] = None,
    changes: Optional[Dict[str, Any]] = None,
    outcome: str = "success",
    actor: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
    tenant_id: Optional[str] = None,
) -> None:
    """
    Add an entry to the current organisation's log (or `tenant_id`'s, or the platform's
    when there is neither). Failures are logged rather than raised, so an audit problem
    never blocks the action itself; a failed write shows as a gap in the numbering.
    """
    chain = tenant_id or current_tenant_or_none() or PLATFORM
    entry: Dict[str, Any] = {
        "at": utcnow(),
        "action": action,
        "outcome": outcome,
        "actor": actor or actor_of(request),
        "address": client_address(request) if request else None,
        "request_id": getattr(getattr(request, "state", None), "request_id", None) if request else None,
        "target": target,
        "changes": changes,
        "details": details,
    }
    try:
        async with _write_lock:
            with tenant_context(chain):
                await _append(entry, action)
    except Exception as e:
        logger.error(f"Could not write audit entry {action}: {e}")


async def _append(entry: Dict[str, Any], action: str) -> None:
    for attempt in range(MAX_ATTEMPTS):
        head = await _head().find_one(HEAD) or {"seq": 0, "hash": GENESIS}
        entry.update(seq=head["seq"] + 1, prev_hash=head["hash"])
        entry["hash"] = _digest(entry)
        # Claim the next number by moving the head on, only if nobody else moved it first.
        try:
            claimed = await _head().update_one(
                {**HEAD, "seq": head["seq"], "hash": head["hash"]} if head["seq"] else {**HEAD, "seq": {"$exists": False}},
                {"$set": {"seq": entry["seq"], "hash": entry["hash"], "at": entry["at"]}},
                upsert=not head["seq"],
            )
        except DuplicateKeyError:
            claimed = None  # another first entry was written at the same moment
        if claimed and (claimed.matched_count or claimed.upserted_id):
            await _log().insert_one(dict(entry))
            return
        # Another process took this number: wait a moment and try the next.
        await asyncio.sleep(random.uniform(0, 0.005 * (attempt + 1)))
    logger.error(f"Could not write audit entry {action}: too much contention")


async def search(
    *,
    action: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 100,
    skip: int = 0,
) -> List[Dict[str, Any]]:
    query: Dict[str, Any] = {}
    if action:
        # "rule" matches every rule action; "rule.created" just that one.
        query["action"] = action if "." in action else {"$regex": f"^{action}\\."}
    if actor_id:
        query["actor.id"] = actor_id
    if target_type:
        query["target.type"] = target_type
    if target_id:
        query["target.id"] = target_id
    if since or until:
        query["at"] = {**({"$gte": since} if since else {}), **({"$lte": until} if until else {})}
    cursor = _log().find(query, {"_id": 0, "tenant_id": 0}).sort("seq", -1).skip(skip).limit(limit)
    return await cursor.to_list(limit)


def _recent(at: Optional[datetime]) -> bool:
    if at is None:
        return False
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return (utcnow() - at).total_seconds() < WRITE_GRACE_SECONDS


async def verify() -> Dict[str, Any]:
    """Walk the chain from the start. Reports the first entry that does not follow from the one before."""
    expected_prev, expected_seq, checked = GENESIS, 1, 0
    still_writing = {"ok": True, "problem": None, "note": "Entries are still being written; check again in a moment"}
    async for entry in _log().find({}, {"_id": 0}).sort("seq", 1):
        if entry["seq"] != expected_seq:
            if _recent(entry.get("at")):
                return {**still_writing, "checked": checked}
            return {"ok": False, "checked": checked, "problem": f"Entries {expected_seq} to {entry['seq'] - 1} are missing"}
        if entry.get("prev_hash") != expected_prev:
            return {"ok": False, "checked": checked, "problem": f"Entry {entry['seq']} does not follow entry {expected_seq - 1}"}
        if _digest(entry) != entry.get("hash"):
            return {"ok": False, "checked": checked, "problem": f"Entry {entry['seq']} has been altered"}
        expected_prev, expected_seq, checked = entry["hash"], expected_seq + 1, checked + 1
    head = await _head().find_one(HEAD)
    if head and head.get("seq", 0) != checked:
        if _recent(head.get("at")):
            return {**still_writing, "checked": checked}
        return {"ok": False, "checked": checked, "problem": f"The log should end at entry {head['seq']}; entries after {checked} are missing"}
    return {"ok": True, "checked": checked, "problem": None}


SECRET_FIELDS = {"password", "new_password", "current_password", "passwordHash", "key", "token"}
MAX_DETAIL_LENGTH = 500


def _summary(value: Any) -> Any:
    """A request body as recorded: secrets removed, long values shortened."""
    if isinstance(value, dict):
        return {k: ("[hidden]" if k in SECRET_FIELDS else _summary(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_summary(v) for v in value[:20]]
    if isinstance(value, str) and len(value) > MAX_DETAIL_LENGTH:
        return value[:MAX_DETAIL_LENGTH] + "…"
    return value


def audited(area: str):
    """
    A router-wide dependency that records every change made through the router: the
    route (as the action, `<area>.<route name>`), the item it acted on (from the path),
    the fields sent, and whether it went through. Reads are not recorded.
    """
    target_type = area[:-1] if area.endswith("s") else area

    async def dependency(request: Request):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            yield
            return
        route = request.scope.get("route")
        action = f"{area}.{getattr(route, 'name', request.method.lower())}"
        params = dict(request.path_params)
        target_id = next(iter(params.values()), None)
        details: Dict[str, Any] = {"path_params": params} if len(params) > 1 else {}
        if request.query_params:
            details["query"] = dict(request.query_params)
        try:
            body = await request.json() if await request.body() else None
        except ValueError:
            body = None
        if body is not None:
            details["request"] = _summary(body)
        target = {"type": target_type, "id": target_id} if target_id else None
        try:
            yield
        except Exception as e:
            code = getattr(e, "status_code", 500)
            await record(action, request, target=target, outcome="denied" if code in (401, 403) else "failed",
                         details={**details, "status": code})
            raise
        # A route that creates something names it, since it is not in the path.
        target = getattr(request.state, "audit_target", None) or target
        await record(action, request, target=target, details=details or None)

    return dependency


def created(request: Request, kind: str, item_id: str, name: Optional[str] = None) -> None:
    """For a route that creates something: record what, as the audit entry's target."""
    request.state.audit_target = {"type": kind, "id": item_id, **({"name": name} if name else {})}
