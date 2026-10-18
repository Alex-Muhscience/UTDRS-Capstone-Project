"""
Multi-factor authentication: a code from an authenticator app (TOTP, RFC 6238), or a
single-use recovery code, after the password.

The TOTP secret is stored encrypted (utils/crypto.py, bound to the user), so setting up
MFA needs ENCRYPTION_KEY. A code is accepted in the 30-second step it belongs to or the
one either side (clock drift), and only once: the last step used is recorded. Recovery
codes are random, shown once when made, and stored only as hashes; using one removes it.

An organisation can require MFA. Someone without it then signs in to a restricted session
that can do nothing but set it up (utils.security.get_current_user).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from bson import ObjectId

from core.database.connection import get_database
from core.services import tenants
from core.tenancy import current_tenant, scoped
from utils import crypto
from utils.time import utcnow

ISSUER = "UTDRS"
DIGITS = 6
STEP_SECONDS = 30
DRIFT_STEPS = 1
RECOVERY_CODES = 10


class MfaError(ValueError):
    """Something about MFA cannot be done; the message says why, for people."""


# ---------------------------------------------------------------------------
# TOTP, RFC 6238 (HMAC-SHA1, 6 digits, 30 seconds: what authenticator apps expect)

def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def matching_step(secret: str, code: str, now: Optional[float] = None) -> Optional[int]:
    """The time step `code` belongs to, if it is current (allowing for drift); None otherwise."""
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // STEP_SECONDS)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, account: str, organisation: str) -> str:
    label = quote(f"{ISSUER} ({organisation}):{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"


# ---------------------------------------------------------------------------
# Recovery codes

def _hash(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace("-", "").replace(" ", "").encode()).hexdigest()


def new_recovery_codes() -> Tuple[List[str], List[str]]:
    """Codes to show once (xxxx-xxxx), and their hashes to keep."""
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = base64.b32encode(secrets.token_bytes(5)).decode().lower()
        codes.append(f"{raw[:4]}-{raw[4:8]}")
    return codes, [_hash(c) for c in codes]


# ---------------------------------------------------------------------------
# Accounts

def _users():
    return scoped(get_database(), "users")


def _context(user_id: str) -> str:
    return f"mfa:{user_id}"


async def required() -> bool:
    tenant = await tenants.get(current_tenant()) or {}
    return bool((tenant.get("security") or {}).get("require_mfa"))


def enabled(user: Dict[str, Any]) -> bool:
    return bool((user.get("mfa") or {}).get("enabled"))


async def status(user: Dict[str, Any]) -> Dict[str, Any]:
    mfa = user.get("mfa") or {}
    return {
        "enabled": bool(mfa.get("enabled")),
        "enabled_at": mfa.get("enabled_at"),
        "recovery_codes_left": len(mfa.get("recovery_codes") or []),
        "required_by_organisation": await required(),
        "encryption_available": crypto.available(),
    }


async def start_setup(user: Dict[str, Any]) -> Dict[str, str]:
    """A new secret to put in an authenticator app; MFA is on only once a code from it is confirmed."""
    if enabled(user):
        raise MfaError("Multi-factor authentication is already on; turn it off first to set it up again")
    if not crypto.available():
        raise MfaError("Multi-factor authentication needs ENCRYPTION_KEY set on the gateway")
    secret = new_secret()
    user_id = str(user["_id"])
    await _users().update_one({"_id": ObjectId(user_id)}, {"$set": {"mfa.pending_secret": crypto.encrypt(secret, _context(user_id))}})
    tenant = await tenants.get(current_tenant()) or {}
    return {"secret": secret, "otpauth_uri": otpauth_uri(secret, user.get("email") or user["username"], tenant.get("name", ""))}


async def confirm_setup(user: Dict[str, Any], code: str) -> List[str]:
    """Turn MFA on with the first code from the app. Returns the recovery codes, shown once."""
    pending = (user.get("mfa") or {}).get("pending_secret")
    if not pending:
        raise MfaError("Start setting up multi-factor authentication first")
    user_id = str(user["_id"])
    secret = crypto.decrypt(pending, _context(user_id))
    step = matching_step(secret, code)
    if step is None:
        raise MfaError("That code is not right; check the time on your phone and try the newest code")
    codes, hashes = new_recovery_codes()
    await _users().update_one({"_id": ObjectId(user_id)}, {"$set": {"mfa": {
        "enabled": True, "secret": pending, "last_step": step, "recovery_codes": hashes, "enabled_at": utcnow(),
    }}})
    return codes


async def verify(user: Dict[str, Any], code: str) -> Optional[str]:
    """
    Check a second factor for `user`: "totp" or "recovery" when it is right (and now used
    up), None when it is not.
    """
    mfa = user.get("mfa") or {}
    if not mfa.get("enabled"):
        return None
    user_id = str(user["_id"])
    secret = crypto.decrypt(mfa["secret"], _context(user_id))
    step = matching_step(secret, code)
    if step is not None:
        # Once: only a step later than the last one used, claimed atomically.
        claimed = await _users().update_one(
            {"_id": ObjectId(user_id), "mfa.last_step": {"$lt": step}}, {"$set": {"mfa.last_step": step}}
        )
        return "totp" if claimed.modified_count else None
    hashed = _hash(code)
    used = await _users().update_one(
        {"_id": ObjectId(user_id), "mfa.recovery_codes": hashed}, {"$pull": {"mfa.recovery_codes": hashed}}
    )
    return "recovery" if used.modified_count else None


async def new_codes(user: Dict[str, Any], code: str) -> List[str]:
    if not await verify(user, code):
        raise MfaError("That code is not right")
    codes, hashes = new_recovery_codes()
    await _users().update_one({"_id": user["_id"]}, {"$set": {"mfa.recovery_codes": hashes}})
    return codes


async def disable(user: Dict[str, Any], code: str) -> None:
    if await required():
        raise MfaError("Your organisation requires multi-factor authentication")
    if not await verify(user, code):
        raise MfaError("That code is not right")
    await _users().update_one({"_id": user["_id"]}, {"$unset": {"mfa": ""}})


async def reset(user_id: str) -> bool:
    """An administrator turns someone's MFA off (a lost phone): they set it up again at their next sign-in if required."""
    if not ObjectId.is_valid(user_id):
        return False
    return bool((await _users().update_one({"_id": ObjectId(user_id)}, {"$unset": {"mfa": ""}})).matched_count)


async def set_required(value: bool, admin: Dict[str, Any]) -> None:
    if value and not enabled(admin):
        raise MfaError("Set up multi-factor authentication for yourself first, so you are not locked out")
    await get_database()["tenants"].update_one({"_id": ObjectId(current_tenant())}, {"$set": {"security.require_mfa": value}})
