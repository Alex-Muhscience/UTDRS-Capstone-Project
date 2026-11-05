"""
Sessions: what signing in creates, and what signing out (or an administrator) ends.

Signing in starts a session and returns two tokens:
- an access token (a JWT naming the session, ACCESS_TOKEN_EXPIRE_MINUTES long), sent with
  every request; each request checks that its session has not been ended;
- a refresh token (random, stored only as a hash), exchanged at /auth/refresh for a new
  pair. Each refresh token works once: a refresh token used a second time means it was
  copied, so the session is ended at once (refresh-token rotation with reuse detection).

A session ends when its person signs out, after SESSION_IDLE_MINUTES without a refresh,
SESSION_MAX_HOURS after signing in, when they change their password (their other
sessions), and when an administrator signs them out, resets their password or MFA, or
deactivates them. Ended sessions are kept for a while (they say who was signed in from
where), then removed.
"""
import hashlib
import secrets
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId
from fastapi import Request
from pymongo import ReturnDocument

from config import settings
from core.database.connection import get_database
from core.tenancy import scoped, tenant_context
from utils.client_address import client_address
from utils.time import utcnow

COLLECTION = "sessions"
KEPT_AFTER_ENDING = timedelta(days=30)
PREVIOUS_KEPT = 10  # refresh tokens remembered per session, to recognise reuse


class SessionEnded(Exception):
    """The session cannot be used; the message says why, for people."""


def _sessions():
    return scoped(get_database(), COLLECTION)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def ensure_indexes() -> None:
    sessions = get_database()[COLLECTION]
    await sessions.create_index("refresh_hash", unique=True)
    await sessions.create_index("previous_hashes")
    await sessions.create_index([("tenant_id", 1), ("user_id", 1), ("ended_at", 1)])
    await sessions.create_index("purge_at", expireAfterSeconds=0)


def _device(user_agent: str) -> str:
    """A short, readable name for the browser and system, from the User-Agent."""
    ua = user_agent or ""
    browser = next((name for key, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                                           ("Safari/", "Safari")) if key in ua), None)
    system = next((name for key, name in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                                          ("Mac OS X", "macOS"), ("Linux", "Linux")) if key in ua), None)
    if browser or system:
        return " on ".join(p for p in (browser, system) if p)
    return ua[:60] or "Unknown device"


async def start(user: Dict[str, Any], request: Optional[Request], mfa: Optional[str] = None) -> Tuple[str, str]:
    """A new session for `user`. Returns its id and its first refresh token."""
    now = utcnow()
    refresh = secrets.token_urlsafe(32)
    user_agent = request.headers.get("user-agent", "") if request else ""
    doc = {
        "user_id": str(user["_id"]),
        "username": user.get("username"),
        "created_at": now,
        "last_used_at": now,
        "expires_at": now + timedelta(hours=settings.SESSION_MAX_HOURS),
        "address": client_address(request) if request else None,
        "device": _device(user_agent),
        "user_agent": user_agent[:300],
        "mfa": mfa,
        "refresh_hash": _hash(refresh),
        "previous_hashes": [],
        "ended_at": None,
        "end_reason": None,
        "purge_at": now + timedelta(hours=settings.SESSION_MAX_HOURS) + KEPT_AFTER_ENDING,
    }
    with tenant_context(user["tenant_id"]):
        result = await _sessions().insert_one(doc)
    return str(result.inserted_id), refresh


def _ended(session: Dict[str, Any], now) -> Optional[str]:
    if session.get("ended_at"):
        return session.get("end_reason") or "Your session has ended"
    if session["expires_at"] <= now:
        return "Your session reached its time limit: sign in again"
    if session["last_used_at"] + timedelta(minutes=settings.SESSION_IDLE_MINUTES) <= now:
        return "You were signed out after a period of inactivity"
    return None


async def refresh(token: str) -> Tuple[Dict[str, Any], str]:
    """
    Exchange a refresh token for a new one. Returns the session and the new token.
    A token that was already used ends its session (it has been copied).
    """
    raw = get_database()[COLLECTION]  # the token says which organisation; nothing else does yet
    hashed = _hash(token)
    now = utcnow()
    session = await raw.find_one({"refresh_hash": hashed})
    if session is None:
        reused = await raw.find_one({"previous_hashes": hashed})
        if reused and not reused.get("ended_at"):
            await _end(raw, reused["_id"], "This session was ended because its sign-in was used from two places")
            from core.services import audit

            await audit.record("auth.session_reuse_detected", actor={"type": "user", "id": reused["user_id"], "name": reused.get("username")},
                               outcome="denied", target={"type": "session", "id": str(reused["_id"])}, tenant_id=reused["tenant_id"])
        raise SessionEnded("Your session has ended: sign in again")
    reason = _ended(session, now)
    if reason:
        raise SessionEnded(reason)
    new = secrets.token_urlsafe(32)
    rotated = await raw.find_one_and_update(
        {"_id": session["_id"], "refresh_hash": hashed, "ended_at": None},
        {"$set": {"refresh_hash": _hash(new), "last_used_at": now},
         "$push": {"previous_hashes": {"$each": [hashed], "$slice": -PREVIOUS_KEPT}}},
        return_document=ReturnDocument.AFTER,
    )
    if rotated is None:  # used at the same moment elsewhere
        raise SessionEnded("Your session has ended: sign in again")
    return rotated, new


async def is_active(session_id: str) -> Optional[str]:
    """None when the session can be used; otherwise why not."""
    if not ObjectId.is_valid(session_id):
        return "Your session has ended"
    session = await get_database()[COLLECTION].find_one({"_id": ObjectId(session_id)}, {"ended_at": 1, "end_reason": 1, "expires_at": 1, "last_used_at": 1})
    if session is None:
        return "Your session has ended"
    # Idle time is counted between refreshes; an access token is valid for its few minutes.
    if session.get("ended_at"):
        return session.get("end_reason") or "Your session has ended"
    if session["expires_at"] <= utcnow():
        return "Your session reached its time limit: sign in again"
    return None


async def _end(collection, session_id, reason: str) -> bool:
    result = await collection.update_one({"_id": session_id, "ended_at": None}, {"$set": {"ended_at": utcnow(), "end_reason": reason}})
    return bool(result.modified_count)


async def end(session_id: str, reason: str = "You signed out", user_id: Optional[str] = None) -> bool:
    """End one session of the current organisation (only `user_id`'s, when given)."""
    if not ObjectId.is_valid(session_id):
        return False
    query: Dict[str, Any] = {"_id": ObjectId(session_id), "ended_at": None}
    if user_id:
        query["user_id"] = user_id
    result = await _sessions().update_one(query, {"$set": {"ended_at": utcnow(), "end_reason": reason}})
    return bool(result.modified_count)


async def end_all(user_id: str, reason: str, keep: Optional[str] = None) -> int:
    """End every session of `user_id` in the current organisation, except `keep`."""
    query: Dict[str, Any] = {"user_id": user_id, "ended_at": None}
    if keep and ObjectId.is_valid(keep):
        query["_id"] = {"$ne": ObjectId(keep)}
    result = await _sessions().update_many(query, {"$set": {"ended_at": utcnow(), "end_reason": reason}})
    return result.modified_count


async def list_for(user_id: str, current: Optional[str] = None) -> List[Dict[str, Any]]:
    """`user_id`'s sessions that can still be used, most recently active first."""
    now = utcnow()
    found = await _sessions().find(
        {"user_id": user_id, "ended_at": None, "expires_at": {"$gt": now},
         "last_used_at": {"$gt": now - timedelta(minutes=settings.SESSION_IDLE_MINUTES)}},
        {"refresh_hash": 0, "previous_hashes": 0},
    ).sort("last_used_at", -1).to_list(100)
    return [{**s, "current": str(s["_id"]) == current} for s in found]
