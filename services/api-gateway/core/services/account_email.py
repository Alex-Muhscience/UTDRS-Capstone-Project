"""
Emails about a person's account: resetting a forgotten password, and verifying an email
address. Both send a link with a single-use token.

Tokens are random, stored only as hashes (in `account_tokens`, removed after they
expire), and each works once. A new token of the same kind replaces the last one. The
emails go through the notification outbox (retried like any other), and their text, which
holds the link, is removed once sent.

Asking for a reset never says whether the account exists, and is limited per account
(RESET_EMAILS_PER_HOUR). A reset ends every session of the account; it does not get
round multi-factor authentication, which is still asked for at the next sign-in.
"""
import hashlib
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional

from bson import ObjectId

from config import settings
from core.database.connection import get_database
from core.services import notifications
from core.tenancy import tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "account_tokens"
RESET, VERIFY = "reset_password", "verify_email"
LIFETIME = {RESET: timedelta(minutes=30), VERIFY: timedelta(days=2)}
RESET_EMAILS_PER_HOUR = 3


class InvalidToken(ValueError):
    """The link is wrong, used or expired; the message says so, for people."""


def _tokens():
    return get_database()[COLLECTION]  # looked up by the token, before anyone's organisation is known


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def ensure_indexes() -> None:
    await _tokens().create_index("token_hash", unique=True)
    await _tokens().create_index([("user_id", 1), ("purpose", 1), ("created_at", -1)])
    await _tokens().create_index("expires_at", expireAfterSeconds=24 * 3600)  # kept a day after expiry, for the hourly limit


def available() -> bool:
    """Whether account emails can be sent at all (an SMTP server is configured)."""
    return notifications.configured()


async def _issue(user: Dict[str, Any], purpose: str) -> str:
    now = utcnow()
    token = secrets.token_urlsafe(32)
    # Only the newest link of each kind works.
    await _tokens().update_many({"user_id": str(user["_id"]), "purpose": purpose, "used_at": None}, {"$set": {"used_at": now, "replaced": True}})
    await _tokens().insert_one({
        "token_hash": _hash(token), "purpose": purpose, "user_id": str(user["_id"]), "tenant_id": user["tenant_id"],
        "email": user.get("email"), "created_at": now, "expires_at": now + LIFETIME[purpose], "used_at": None,
    })
    return token


async def _send(user: Dict[str, Any], subject: str, text: str) -> None:
    with tenant_context(user["tenant_id"]):
        await notifications.enqueue_account_email(user, subject, text)


async def send_password_reset(user: Dict[str, Any]) -> bool:
    """Email `user` a link to choose a new password. False when it was not sent (limit, no email)."""
    if not available() or not user.get("email") or not user.get("active", True):
        return False
    recent = await _tokens().count_documents({"user_id": str(user["_id"]), "purpose": RESET, "created_at": {"$gte": utcnow() - timedelta(hours=1)}})
    if recent >= RESET_EMAILS_PER_HOUR:
        logger.info(f"Password reset for {user['_id']} not sent: {RESET_EMAILS_PER_HOUR} already in the last hour")
        return False
    token = await _issue(user, RESET)
    minutes = int(LIFETIME[RESET].total_seconds() // 60)
    await _send(user, "[UTDRS] Reset your password", (
        f"Someone asked to reset the password of the UTDRS account {user['username']}.\n\n"
        f"To choose a new password, open this link within {minutes} minutes:\n\n"
        f"{_link('/reset-password', token)}\n\n"
        "The link works once. Resetting signs the account out everywhere.\n\n"
        "If it was not you, ignore this email: your password stays as it is.\n"
    ))
    return True


async def send_verification(user: Dict[str, Any]) -> bool:
    """Email `user` a link to confirm their email address. False when it was not sent."""
    if not available() or not user.get("email"):
        return False
    token = await _issue(user, VERIFY)
    await _send(user, "[UTDRS] Confirm your email address", (
        f"Confirm that {user['email']} is the email address of the UTDRS account {user['username']}:\n\n"
        f"{_link('/verify-email', token)}\n\n"
        "The link works for two days. If you did not sign up for UTDRS, ignore this email.\n"
    ))
    return True


def _link(path: str, token: str) -> str:
    return f"{settings.DASHBOARD_URL.rstrip('/')}{path}#token={token}"


async def use(token: str, purpose: str) -> Dict[str, Any]:
    """
    Spend a token: the record it belongs to (with user_id and tenant_id), now used.
    Raises InvalidToken when it is wrong, already used, replaced or expired.
    """
    now = utcnow()
    record = await _tokens().find_one_and_update(
        {"token_hash": _hash(token or ""), "purpose": purpose, "used_at": None, "expires_at": {"$gt": now}},
        {"$set": {"used_at": now}},
    )
    if record is None:
        raise InvalidToken("This link has expired or has already been used. Ask for a new one.")
    return record


async def mark_verified(user_id: str, email: Optional[str]) -> bool:
    """Record the address as verified, if it is still the account's address."""
    result = await get_database()["users"].update_one(
        {"_id": ObjectId(user_id), "email": email}, {"$set": {"email_verified": True, "email_verified_at": utcnow()}}
    )
    return bool(result.matched_count)
