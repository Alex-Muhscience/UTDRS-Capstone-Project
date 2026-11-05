"""
Idempotency keys: a client that sends `Idempotency-Key` with a request can send it again
(after a timeout, say) and get the first answer instead of doing the work twice.

A key belongs to whoever sent it (a person or an API key) and their organisation, and is
kept for KEPT. The same key with a different body is a mistake (409), as is the same key
while the first request is still being worked on (409, try again shortly).
"""
import hashlib
from datetime import timedelta
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException, Request, status
from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from core.tenancy import current_tenant
from utils.time import utcnow

COLLECTION = "idempotency_keys"
KEPT = timedelta(hours=24)
MAX_KEY_LENGTH = 200


async def ensure_indexes() -> None:
    await get_database()[COLLECTION].create_index("created_at", expireAfterSeconds=int(KEPT.total_seconds()))


def _id(request: Request, key: str) -> str:
    principal = getattr(request.state, "principal", None) or {}
    owner = f"{current_tenant()}|{principal.get('type')}:{principal.get('id')}|{request.method} {request.url.path}"
    return hashlib.sha256(f"{owner}|{key}".encode()).hexdigest()


async def begin(request: Request, body: bytes) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Start a request that may carry an Idempotency-Key. Returns the record's id to finish
    (None without a key), and the stored answer when this is a repeat.
    """
    key = request.headers.get("idempotency-key")
    if not key:
        return None, None
    if len(key) > MAX_KEY_LENGTH:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Idempotency-Key is at most {MAX_KEY_LENGTH} characters")
    record_id = _id(request, key)
    body_hash = hashlib.sha256(body).hexdigest()
    keys = get_database()[COLLECTION]
    try:
        await keys.insert_one({"_id": record_id, "body_hash": body_hash, "state": "working", "created_at": utcnow()})
        return record_id, None
    except DuplicateKeyError:
        existing = await keys.find_one({"_id": record_id}) or {}
    if existing.get("body_hash") != body_hash:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This Idempotency-Key was used with a different request")
    if existing.get("state") != "done":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A request with this Idempotency-Key is still being worked on; try again shortly",
                            headers={"Retry-After": "2"})
    return record_id, {"status_code": existing["status_code"], "content": existing["content"]}


async def finish(record_id: Optional[str], status_code: int, content: Any) -> None:
    if record_id:
        await get_database()[COLLECTION].update_one({"_id": record_id}, {"$set": {"state": "done", "status_code": status_code, "content": content}})


async def abandon(record_id: Optional[str]) -> None:
    """The request failed: the key can be used again."""
    if record_id:
        await get_database()[COLLECTION].delete_one({"_id": record_id, "state": "working"})
