from datetime import datetime, timezone


def utcnow() -> datetime:
    """The current time in UTC, timezone-aware (datetime.utcnow() is deprecated)."""
    return datetime.now(timezone.utc)
