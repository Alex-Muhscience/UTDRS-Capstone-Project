"""
One process at a time for start-up tasks.

The gateway runs as several processes (gunicorn workers, replicas), each running the
start-up tasks: creating the default tenant, moving data from before tenancy into it,
creating indexes, the first administrator. Run at once, they race: two processes can
each create the default tenant. This lock, held in MongoDB, makes them take turns; the
later ones find the work done. It expires, so a process that dies holding it does not
stop the others for long.
"""
import asyncio
import os
import socket
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta

from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

LEASE = timedelta(seconds=60)
WAIT_SECONDS = 120


@asynccontextmanager
async def startup_lock(name: str = "startup"):
    locks = get_database()["platform_locks"]
    owner = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
    deadline = asyncio.get_running_loop().time() + WAIT_SECONDS
    while True:
        now = utcnow()
        # Take an expired lock over, or create it.
        await locks.delete_one({"_id": name, "expires_at": {"$lt": now}})
        try:
            await locks.insert_one({"_id": name, "owner": owner, "expires_at": now + LEASE})
            break
        except DuplicateKeyError:
            if asyncio.get_running_loop().time() > deadline:
                raise RuntimeError(f"Waited {WAIT_SECONDS}s for another process's start-up to finish")
            await asyncio.sleep(0.5)
    try:
        yield
    finally:
        await locks.delete_one({"_id": name, "owner": owner})
