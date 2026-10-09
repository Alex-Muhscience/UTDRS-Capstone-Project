from datetime import datetime, timezone


def utcnow() -> datetime:
    """
    The current time in UTC as a naive datetime.

    The engine compares against event timestamps parsed from ISO strings, which are
    normalised to naive UTC on ingestion (core.services.event_processor), so "now"
    must be naive UTC too. datetime.utcnow() itself is deprecated.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_timestamp(value) -> str:
    """
    An event timestamp as a naive-UTC ISO 8601 string, the form the engine stores and
    compares. Accepts datetimes and ISO strings, with or without a UTC offset ("Z" included).
    Anything unparseable becomes the current time.
    """
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            value = None
    if not isinstance(value, datetime):
        return utcnow().isoformat()
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat()
