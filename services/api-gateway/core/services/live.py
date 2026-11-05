"""
Live updates for the dashboard: what changed in an organisation, as it happens.

Whatever is worth telling (a new alert, a case changed, an action waiting for a decision)
is published here, from whichever process it happens in: a web process, an analysis worker.
Each is written to `live_events`, kept for an hour, so it reaches every gateway process
without anything but MongoDB: each process with someone listening reads new entries once a
second and hands them to its listeners in that organisation. A dashboard that lost its
connection says which entry it saw last and gets what it missed.

The stream only says what changed, with an alert's title and severity so the dashboard can
announce it; the dashboard then fetches the data through the API as usual, with the same
permissions as always.
"""
import asyncio
import json
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional, Set

from bson import ObjectId

from core.database.connection import get_database
from core.tenancy import current_tenant_or_none
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "live_events"
KEEP_SECONDS = 3600
POLL_SECONDS = 1.0
LOOKBACK_SECONDS = 10  # entries from other processes can arrive slightly out of order
REPLAY_LIMIT = 200
QUEUE_SIZE = 200
RESYNC = {"id": None, "event": "resync", "data": {}}  # "too much was missed: fetch everything again"


def _collection():
    return get_database()[COLLECTION]


async def ensure_indexes() -> None:
    await _collection().create_index("at", expireAfterSeconds=KEEP_SECONDS)
    await _collection().create_index([("tenant_id", 1), ("_id", 1)])


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


async def publish(event: str, data: Optional[Dict[str, Any]] = None, tenant_id: Optional[str] = None) -> None:
    """Tell the current organisation's dashboards that `event` happened. Never raises."""
    tenant_id = tenant_id or current_tenant_or_none()
    if not tenant_id:
        return
    try:
        await _collection().insert_one({"tenant_id": tenant_id, "event": event, "data": _plain(data or {}), "at": utcnow()})
    except Exception as e:
        logger.warning(f"Could not publish {event} to live updates: {e}")


def _message(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": str(doc["_id"]), "event": doc["event"], "data": doc.get("data") or {}}


async def missed(tenant_id: str, last_id: str) -> List[Dict[str, Any]]:
    """What the organisation's dashboard missed since entry `last_id`; [RESYNC] when that is too much or too old to tell."""
    if not ObjectId.is_valid(last_id):
        return [RESYNC]
    found = await _collection().find({"tenant_id": tenant_id, "_id": {"$gt": ObjectId(last_id)}}).sort("_id", 1).limit(REPLAY_LIMIT + 1).to_list(None)
    if len(found) > REPLAY_LIMIT or ObjectId(last_id).generation_time < utcnow() - timedelta(seconds=KEEP_SECONDS):
        return [RESYNC]
    return [_message(doc) for doc in found]


class Hub:
    """This process's listeners, by organisation, and the one reader that feeds them."""

    def __init__(self) -> None:
        self.listeners: Dict[str, Set[asyncio.Queue]] = {}
        self.task: Optional[asyncio.Task] = None
        self.seen: Dict[str, float] = {}

    def subscribe(self, tenant_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.listeners.setdefault(tenant_id, set()).add(queue)
        if self.task is None or self.task.done():
            self.seen = {}
            self.task = asyncio.create_task(self._read())
        return queue

    def unsubscribe(self, tenant_id: str, queue: asyncio.Queue) -> None:
        queues = self.listeners.get(tenant_id)
        if queues is not None:
            queues.discard(queue)
            if not queues:
                del self.listeners[tenant_id]

    def deliver(self, tenant_id: str, message: Dict[str, Any]) -> None:
        for queue in list(self.listeners.get(tenant_id, ())):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # A listener this far behind is told to fetch everything again.
                while not queue.empty():
                    queue.get_nowait()
                queue.put_nowait(RESYNC)

    async def _read(self) -> None:
        # Only what is published from now on: listeners catch up on the rest themselves.
        start = ObjectId.from_datetime(utcnow())
        while self.listeners:
            try:
                since = max(start, ObjectId.from_datetime(utcnow() - timedelta(seconds=LOOKBACK_SECONDS)))
                cutoff = time.monotonic() - 3 * LOOKBACK_SECONDS
                self.seen = {key: at for key, at in self.seen.items() if at > cutoff}
                async for doc in _collection().find({"_id": {"$gte": since}, "tenant_id": {"$in": list(self.listeners)}}).sort("_id", 1):
                    key = str(doc["_id"])
                    if key in self.seen:
                        continue
                    self.seen[key] = time.monotonic()
                    self.deliver(doc["tenant_id"], _message(doc))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Could not read live updates: {e}")
            await asyncio.sleep(POLL_SECONDS)


hub = Hub()
