"""
Platform operators: the people who run a UTDRS deployment, apart from every organisation.

Operators are not users of any organisation. Their accounts are in `operators`, which no
organisation's administrators, SCIM token or single sign-on can see or change; they sign in
at the operator console with a password and, always, an authenticator code; and their tokens
are signed with a key of their own, for the platform API only (an organisation's token is
never accepted there, nor an operator's anywhere else).

- First sign-in: an operator without a second factor must set one up before anything else.
  A temporary password (a new operator's, or after a reset) must be changed next.
- Sessions: short tokens (OPERATOR_TOKEN_MINUTES), refreshed while the session lasts; a
  session ends after OPERATOR_SESSION_IDLE_MINUTES without use, OPERATOR_SESSION_MAX_HOURS
  after sign-in, or at sign-out, a reset or deactivation.
- The first operator comes from PLATFORM_OPERATOR_USERNAME / _PASSWORD / _EMAIL; operators then
  add each other. PLATFORM_OPERATOR_RESET recovers that account (password from the setting,
  second factor cleared) when every operator is locked out.
"""
import hashlib
import secrets
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import jwt
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from config import settings
from core.database.connection import get_database
from core.services import mfa
from utils import crypto
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

AUDIENCE = "utdrs-platform"
STEP_MINUTES = 5


class OperatorError(ValueError):
    """The operator action cannot be done; the message says why, for people."""


def _operators():
    return get_database()["operators"]


def _sessions():
    return get_database()["operator_sessions"]


async def ensure_indexes() -> None:
    await _operators().create_index("username", unique=True)
    await _operators().create_index("email", unique=True, sparse=True)
    await _sessions().create_index("operator_id")
    await _sessions().create_index("started_at", expireAfterSeconds=30 * 24 * 3600)


def signing_key() -> str:
    """Never the organisations' key: an operator's token is useless to the rest of the API, and theirs here."""
    return settings.OPERATOR_JWT_SECRET or hashlib.sha256(f"{settings.JWT_SECRET}:platform-operators".encode()).hexdigest()


def _mfa_context(operator_id: str) -> str:
    return f"operator-mfa:{operator_id}"


def public(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": str(doc["_id"]), "username": doc["username"], "email": doc.get("email"), "active": doc.get("active", True),
            "mfa": bool((doc.get("mfa") or {}).get("enabled")), "must_change_password": bool(doc.get("must_change_password")),
            "created_at": doc.get("created_at"), "last_sign_in": doc.get("last_sign_in")}


def temporary_password() -> str:
    return secrets.token_urlsafe(12)


def _check_password(password: str) -> None:
    if len(password) < 12:
        raise OperatorError("An operator's password must be at least 12 characters")
    if len(password.encode()) > 72:
        raise OperatorError("Passwords can be at most 72 bytes")


# ---------------------------------------------------------------------------- Accounts

async def create(username: str, email: str, password: str, created_by: Optional[Dict[str, Any]], must_change: bool = True) -> Dict[str, Any]:
    from utils.security import get_password_hash

    username, email = username.strip(), email.strip().lower()
    if len(username) < 3:
        raise OperatorError("Usernames are at least 3 characters")
    _check_password(password)
    doc = {"username": username, "email": email, "password_hash": get_password_hash(password), "active": True, "must_change_password": must_change,
           "created_at": utcnow(), "created_by": created_by}
    try:
        result = await _operators().insert_one(doc)
    except DuplicateKeyError:
        raise OperatorError("That username or email address already belongs to an operator")
    return {**doc, "_id": result.inserted_id}


async def get(operator_id: str) -> Optional[Dict[str, Any]]:
    return await _operators().find_one({"_id": ObjectId(operator_id)}) if ObjectId.is_valid(operator_id) else None


async def list_all() -> List[Dict[str, Any]]:
    return [public(doc) async for doc in _operators().find().sort("username", 1)]


async def _others_active(operator_id: str) -> int:
    return await _operators().count_documents({"active": True, "_id": {"$ne": ObjectId(operator_id)}})


async def set_active(operator_id: str, active: bool, by: Dict[str, Any]) -> Dict[str, Any]:
    doc = await get(operator_id)
    if not doc:
        raise LookupError("Operator not found")
    if not active:
        if operator_id == by["id"]:
            raise OperatorError("You cannot deactivate yourself; ask another operator")
        if not await _others_active(operator_id):
            raise OperatorError("There must be at least one active operator")
        await end_sessions(operator_id, "This operator account has been deactivated")
    await _operators().update_one({"_id": doc["_id"]}, {"$set": {"active": active}})
    return public({**doc, "active": active})


async def reset(operator_id: str, by: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """A new temporary password and no second factor (a lost phone): they set both up at their next sign-in."""
    from utils.security import get_password_hash

    doc = await get(operator_id)
    if not doc:
        raise LookupError("Operator not found")
    if operator_id == by["id"]:
        raise OperatorError("You cannot reset yourself; ask another operator")
    password = temporary_password()
    await _operators().update_one({"_id": doc["_id"]}, {"$set": {"password_hash": get_password_hash(password), "must_change_password": True},
                                                        "$unset": {"mfa": "", "mfa_pending": ""}})
    await end_sessions(operator_id, "Your operator account was reset")
    return public({**doc, "must_change_password": True, "mfa": None}), password


async def change_password(operator: Dict[str, Any], current: str, new: str) -> None:
    from utils.security import get_password_hash, verify_password

    if not verify_password(current, operator["password_hash"]):
        raise OperatorError("Your current password is not right")
    if current == new:
        raise OperatorError("Choose a password different from the current one")
    _check_password(new)
    await _operators().update_one({"_id": operator["_id"]}, {"$set": {"password_hash": get_password_hash(new), "must_change_password": False}})


async def ensure_first() -> None:
    """The deployment's first operator, from PLATFORM_OPERATOR_* (and its recovery, with PLATFORM_OPERATOR_RESET)."""
    from utils.security import get_password_hash

    username, password = settings.PLATFORM_OPERATOR_USERNAME, settings.PLATFORM_OPERATOR_PASSWORD
    if not username:
        if not await _operators().count_documents({}):
            logger.warning("There is no platform operator: set PLATFORM_OPERATOR_USERNAME and PLATFORM_OPERATOR_PASSWORD to create one")
        return
    existing = await _operators().find_one({"username": username})
    if existing:
        if settings.PLATFORM_OPERATOR_RESET and password:
            _check_password(password)
            await _operators().update_one({"_id": existing["_id"]}, {"$set": {"password_hash": get_password_hash(password), "active": True, "must_change_password": True},
                                                                     "$unset": {"mfa": "", "mfa_pending": ""}})
            await end_sessions(str(existing["_id"]), "The operator account was recovered")
            logger.warning(f"Recovered the operator {username} (PLATFORM_OPERATOR_RESET): remove that setting now")
        return
    if not password:
        logger.warning(f"PLATFORM_OPERATOR_USERNAME is set but PLATFORM_OPERATOR_PASSWORD is not; operator {username} was not created")
        return
    try:
        await create(username, settings.PLATFORM_OPERATOR_EMAIL or f"{username}@operators.localdomain", password, None, must_change=False)
    except OperatorError as e:
        raise RuntimeError(f"Cannot create the operator from PLATFORM_OPERATOR_* settings: {e}") from None
    logger.info(f"Created the platform operator {username}")


async def forget_user_platform_flags() -> None:
    """Organisation accounts no longer run the platform (they did, with a flag, before operators)."""
    result = await get_database()["users"].update_many({"platform_admin": {"$exists": True}}, {"$unset": {"platform_admin": ""}})
    if result.modified_count:
        logger.info(f"Removed the platform flag from {result.modified_count} organisation accounts: operators now run the platform")


# ---------------------------------------------------------------------------- Signing in

def _token(claims: Dict[str, Any], minutes: float) -> str:
    now = utcnow()
    return jwt.encode({**claims, "aud": AUDIENCE, "iat": now, "exp": now + timedelta(minutes=minutes), "jti": secrets.token_hex(8)},
                      signing_key(), algorithm="HS256")


def decode(token: str) -> Dict[str, Any]:
    return jwt.decode(token, signing_key(), algorithms=["HS256"], audience=AUDIENCE)


async def password_step(username: str, password: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """After a right password: the operator and what comes next (a code, or setting up a second factor). (None, {}) if wrong."""
    from utils.security import verify_password

    doc = await _operators().find_one({"username": username})
    if not doc or not doc.get("active", True) or not verify_password(password, doc.get("password_hash") or ""):
        return None, {}
    operator_id = str(doc["_id"])
    if (doc.get("mfa") or {}).get("enabled"):
        return doc, {"step": "mfa", "step_token": _token({"sub": operator_id, "purpose": "mfa"}, STEP_MINUTES)}
    secret = mfa.new_secret()
    await _operators().update_one({"_id": doc["_id"]}, {"$set": {"mfa_pending": crypto.encrypt(secret, _mfa_context(operator_id))}})
    label = quote(f"{mfa.ISSUER} platform:{doc['username']}")
    uri = f"otpauth://totp/{label}?secret={secret}&issuer={quote(mfa.ISSUER + ' platform')}&algorithm=SHA1&digits={mfa.DIGITS}&period={mfa.STEP_SECONDS}"
    return doc, {"step": "enrol", "step_token": _token({"sub": operator_id, "purpose": "enrol"}, STEP_MINUTES), "secret": secret, "otpauth_uri": uri}


async def _from_step(step_token: str, purpose: str) -> Dict[str, Any]:
    try:
        claims = decode(step_token)
    except jwt.PyJWTError:
        raise OperatorError("Your sign-in has expired; start again")
    if claims.get("purpose") != purpose:
        raise OperatorError("Your sign-in has expired; start again")
    doc = await get(claims["sub"])
    if not doc or not doc.get("active", True):
        raise OperatorError("Your sign-in has expired; start again")
    return doc


async def code_step(step_token: str, code: str) -> Tuple[Dict[str, Any], str]:
    """The second factor: an authenticator or recovery code. Returns the operator and how ("totp", "recovery")."""
    doc = await _from_step(step_token, "mfa")
    state = doc.get("mfa") or {}
    operator_id = str(doc["_id"])
    secret = crypto.decrypt(state["secret"], _mfa_context(operator_id))
    step = mfa.matching_step(secret, code)
    if step is not None:
        claimed = await _operators().update_one({"_id": doc["_id"], "mfa.last_step": {"$lt": step}}, {"$set": {"mfa.last_step": step}})
        if claimed.modified_count:
            return doc, "totp"
    hashed = mfa._hash(code)
    used = await _operators().update_one({"_id": doc["_id"], "mfa.recovery_codes": hashed}, {"$pull": {"mfa.recovery_codes": hashed}})
    if used.modified_count:
        return doc, "recovery"
    raise OperatorError("That code is not right")


async def enrol_step(step_token: str, code: str) -> Tuple[Dict[str, Any], List[str]]:
    """Setting up the second factor on first sign-in. Returns the operator and recovery codes (shown once)."""
    doc = await _from_step(step_token, "enrol")
    operator_id = str(doc["_id"])
    if not doc.get("mfa_pending"):
        raise OperatorError("Your sign-in has expired; start again")
    secret = crypto.decrypt(doc["mfa_pending"], _mfa_context(operator_id))
    step = mfa.matching_step(secret, code)
    if step is None:
        raise OperatorError("That code is not right; check the time on your phone and try the newest code")
    codes, hashes = mfa.new_recovery_codes()
    await _operators().update_one({"_id": doc["_id"]}, {"$set": {"mfa": {"enabled": True, "secret": doc["mfa_pending"], "last_step": step,
                                                                         "recovery_codes": hashes, "enabled_at": utcnow()}},
                                                        "$unset": {"mfa_pending": ""}})
    return doc, codes


async def start_session(doc: Dict[str, Any], method: str, request) -> Dict[str, Any]:
    now = utcnow()
    session_id = uuid.uuid4().hex
    await _sessions().insert_one({"_id": session_id, "operator_id": str(doc["_id"]), "method": method, "started_at": now, "last_seen_at": now,
                                  "ended_at": None, "address": request.client.host if request and request.client else None,
                                  "user_agent": (request.headers.get("user-agent") or "")[:300] if request else None})
    await _operators().update_one({"_id": doc["_id"]}, {"$set": {"last_sign_in": now}})
    return issue(doc, session_id)


def issue(doc: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    minutes = settings.OPERATOR_TOKEN_MINUTES
    return {"access_token": _token({"sub": str(doc["_id"]), "sid": session_id, "typ": "operator"}, minutes), "token_type": "bearer",
            "expires_in": minutes * 60, "operator": public(doc)}


async def check_session(session_id: str) -> Optional[str]:
    """None while the session lasts (and it is marked used); otherwise why it ended."""
    session = await _sessions().find_one({"_id": session_id})
    if not session:
        return "Your session has ended; sign in again"
    if session.get("ended_at"):
        return session.get("end_reason") or "Your session has ended; sign in again"
    now = utcnow()
    started, seen = session["started_at"], session["last_seen_at"]
    if started.tzinfo is None:
        from datetime import timezone

        started, seen = started.replace(tzinfo=timezone.utc), seen.replace(tzinfo=timezone.utc)
    reason = None
    if now - seen > timedelta(minutes=settings.OPERATOR_SESSION_IDLE_MINUTES):
        reason = "Your session ended after a while without use; sign in again"
    elif now - started > timedelta(hours=settings.OPERATOR_SESSION_MAX_HOURS):
        reason = "Your session has reached its time limit; sign in again"
    if reason:
        await _sessions().update_one({"_id": session_id}, {"$set": {"ended_at": now, "end_reason": reason}})
        return reason
    if now - seen > timedelta(seconds=30):
        await _sessions().update_one({"_id": session_id}, {"$set": {"last_seen_at": now}})
    return None


async def end_session(session_id: str, reason: str = "You signed out") -> None:
    await _sessions().update_one({"_id": session_id, "ended_at": None}, {"$set": {"ended_at": utcnow(), "end_reason": reason}})


async def end_sessions(operator_id: str, reason: str) -> None:
    await _sessions().update_many({"operator_id": operator_id, "ended_at": None}, {"$set": {"ended_at": utcnow(), "end_reason": reason}})
