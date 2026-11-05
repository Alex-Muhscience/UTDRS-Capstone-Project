"""
Handing events to analysis workers through Redis Streams (when REDIS_URL is set).

The queue's record of truth stays on each event in MongoDB (detection_pipeline): its status,
attempts, back-off and replay. The stream only says "this event is ready", so workers learn
of new events the moment they arrive instead of polling the database, and any number of
them can share the work: each entry goes to one worker of the consumer group.

A worker acknowledges an entry once the event's outcome is recorded (analysed, or queued
again with back-off). An entry a worker took but never acknowledged (it died) is claimed by
another after STALE_MS. If Redis loses entries, or is unreachable when an event is stored,
nothing is lost: the database sweep (analyse_periodically) still finds every queued event,
only later.
"""
from typing import List, Optional, Tuple

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

STREAM = "utdrs:analysis"
GROUP = "analysers"
STALE_MS = 2 * 60 * 1000  # as the queue's lease: an entry this long unacknowledged is taken over
MAX_LENGTH = 1_000_000  # entries kept (approximately); far beyond any backlog the workers would leave

_client = None


def enabled() -> bool:
    return bool(settings.REDIS_URL)


def client():
    global _client
    if _client is None:
        import redis.asyncio as redis

        _client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=10, socket_connect_timeout=5)
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def ensure_group() -> None:
    from redis.exceptions import ResponseError

    try:
        await client().xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except ResponseError as e:
        if "BUSYGROUP" not in str(e):  # it exists already
            raise


async def publish(event_ids: List[str]) -> bool:
    """Tell the workers these events are ready. False when Redis could not be reached (the sweep finds them later)."""
    if not enabled() or not event_ids:
        return False
    try:
        async with client().pipeline(transaction=False) as pipe:
            for event_id in event_ids:
                pipe.xadd(STREAM, {"event_id": event_id}, maxlen=MAX_LENGTH, approximate=True)
            await pipe.execute()
        return True
    except Exception as e:  # the database sweep is the safety net
        logger.warning(f"Could not publish {len(event_ids)} events for analysis: {e}")
        return False


async def take(consumer: str, count: int, block_ms: int) -> List[Tuple[str, str]]:
    """Entries for this worker: first any another worker left unacknowledged too long, then new ones (waiting up to block_ms)."""
    redis = client()
    claimed = await redis.xautoclaim(STREAM, GROUP, consumer, min_idle_time=STALE_MS, start_id="0-0", count=count)
    entries = claimed[1] if claimed else []
    if not entries:
        found = await redis.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=count, block=block_ms)
        entries = found[0][1] if found else []
    return [(entry_id, fields.get("event_id", "")) for entry_id, fields in entries if fields]


async def done(entry_ids: List[str]) -> None:
    if entry_ids:
        await client().xack(STREAM, GROUP, *entry_ids)


async def status() -> Optional[dict]:
    """The stream's length and what is taken but not yet acknowledged, for metrics."""
    if not enabled():
        return None
    try:
        redis = client()
        pending = await redis.xpending(STREAM, GROUP)
        return {"length": await redis.xlen(STREAM), "pending": int(pending.get("pending", 0)) if isinstance(pending, dict) else 0}
    except Exception:
        return None
