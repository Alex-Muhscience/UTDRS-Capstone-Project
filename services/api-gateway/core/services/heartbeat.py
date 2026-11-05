"""
Heartbeats of the gateway's background loops: each round of each loop records when it ran,
how often it should, and whether it failed (in `heartbeats`, one document per loop). A loop
that has not run for three of its rounds has stopped; platform_health alerts on it, and
/metrics reports it.
"""
import os
import socket
from typing import Any, Dict, List, Optional

from core.database.connection import get_database
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "heartbeats"
PROCESS = f"{socket.gethostname()}:{os.getpid()}"


async def beat(name: str, interval_seconds: float, error: Optional[BaseException] = None) -> None:
    """Record a round of loop `name`. Never raises: a heartbeat must not stop the loop."""
    now = utcnow()
    fields: Dict[str, Any] = {"at": now, "interval_seconds": interval_seconds, "process": PROCESS, "ok": error is None}
    if error is None:
        fields["last_ok_at"] = now
        fields["error"] = None
    else:
        fields["error"] = f"{error.__class__.__name__}: {error}"[:500]
    try:
        await get_database()[COLLECTION].update_one({"_id": name}, {"$set": fields}, upsert=True)
    except Exception as e:
        logger.warning(f"Could not record the heartbeat of {name}: {e}")


def stale_after(interval_seconds: float) -> float:
    """Seconds without a round after which a loop counts as stopped: three rounds, and at least five minutes."""
    return max(3 * interval_seconds, 300)


async def all_loops() -> List[Dict[str, Any]]:
    now = utcnow()
    loops = await get_database()[COLLECTION].find().to_list(100)
    for loop in loops:
        at = loop["at"]
        at = at if at.tzinfo else at.replace(tzinfo=now.tzinfo)
        loop["age_seconds"] = (now - at).total_seconds()
        loop["stale"] = loop["age_seconds"] > stale_after(loop.get("interval_seconds") or 60)
    return loops
