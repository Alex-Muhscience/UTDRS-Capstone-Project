"""
Slows down password guessing.

Failed sign-ins are counted per account and address, and per address alone, in
MongoDB (so every gateway process and replica shares the counts). Over either limit,
sign-in is refused until the window that started with the first failure ends. Counting
by address as well as account means guessing one account from one address is stopped
quickly, while nobody can lock a person out from somewhere else just by using their name.
"""
from datetime import timedelta
from typing import Optional

from pymongo import ReturnDocument

from config import settings
from core.database.connection import get_database
from utils.time import utcnow

COLLECTION = "login_failures"


def _keys(username: str, address: str):
    return [
        (f"account:{username.lower()}|{address}", settings.LOGIN_MAX_FAILURES_PER_ACCOUNT),
        (f"address:{address}", settings.LOGIN_MAX_FAILURES_PER_ADDRESS),
    ]


async def ensure_indexes() -> None:
    # Counters remove themselves once their window has passed.
    await get_database()[COLLECTION].create_index("expires_at", expireAfterSeconds=0)


async def retry_after(username: str, address: str) -> Optional[int]:
    """Seconds until this sign-in may be tried again, or None if it may be tried now."""
    now = utcnow()
    wait = 0
    for key, limit in _keys(username, address):
        doc = await get_database()[COLLECTION].find_one({"_id": key})
        if doc and doc["count"] >= limit and doc["expires_at"] > now:
            wait = max(wait, int((doc["expires_at"] - now).total_seconds()) + 1)
    return wait or None


async def record_failure(username: str, address: str) -> None:
    now = utcnow()
    window = timedelta(seconds=settings.LOGIN_FAILURE_WINDOW_SECONDS)
    for key, _ in _keys(username, address):
        # One atomic update: start a new window if the last one has ended, else count.
        await get_database()[COLLECTION].find_one_and_update(
            {"_id": key},
            [
                {
                    "$set": {
                        "expired": {"$or": [{"$not": ["$expires_at"]}, {"$lte": ["$expires_at", now]}]},
                    }
                },
                {
                    "$set": {
                        "count": {"$cond": ["$expired", 1, {"$add": ["$count", 1]}]},
                        "expires_at": {"$cond": ["$expired", now + window, "$expires_at"]},
                    }
                },
                {"$unset": "expired"},
            ],
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )


async def record_success(username: str, address: str) -> None:
    """A correct password clears that account's count from that address."""
    key, _ = _keys(username, address)[0]
    await get_database()[COLLECTION].delete_one({"_id": key})
