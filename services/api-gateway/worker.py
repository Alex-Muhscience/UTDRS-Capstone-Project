"""
An analysis worker: sends queued events to the core engine, apart from the API processes.

    python worker.py

Run as many as the load needs, each with the same configuration as the gateway. With
REDIS_URL, each runs ANALYSIS_WORKERS consumers of the analysis stream, which hand events
over as they arrive, and sweeps the database every ANALYSIS_SWEEP_SECONDS for retries that
are due (and anything the stream missed). Without it, each sweeps every
ANALYSIS_INTERVAL_SECONDS. Set ANALYSIS_IN_API to false on the API processes, so they
serve requests only. Stops cleanly on SIGTERM: work in hand is finished, or left to be
taken over.
"""
import asyncio
import os
import signal
import socket
from contextlib import suppress

from config import settings
from core.database.connection import close_mongo_connection, connect_to_mongo
from core.services import analysis_stream, detection_pipeline, heartbeat
from utils.logger import get_logger

logger = get_logger("worker")


async def _beat(stop: asyncio.Event) -> None:
    while not stop.is_set():
        await heartbeat.beat("analysis_worker", 30)
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=30)


async def main() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    await connect_to_mongo()
    name = f"{socket.gethostname()}:{os.getpid()}"
    tasks = [asyncio.create_task(detection_pipeline.analyse_periodically()), asyncio.create_task(_beat(stop))]
    consumers = []
    if analysis_stream.enabled():
        await analysis_stream.ensure_group()
        consumers = [asyncio.create_task(detection_pipeline.analyse_from_stream(f"{name}:{i}", stop)) for i in range(max(1, settings.ANALYSIS_WORKERS))]
        logger.info(f"Analysis worker {name}: {len(consumers)} stream consumers, sweeping every {settings.ANALYSIS_SWEEP_SECONDS} s")
    else:
        logger.info(f"Analysis worker {name}: sweeping every {settings.ANALYSIS_INTERVAL_SECONDS} s (no REDIS_URL)")
    await stop.wait()
    logger.info("Stopping: finishing the work in hand")
    await asyncio.gather(*consumers, return_exceptions=True)  # each stops after its current batch
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await analysis_stream.close()
    await close_mongo_connection()


if __name__ == "__main__":
    asyncio.run(main())
