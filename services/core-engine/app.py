import logging
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import Depends, FastAPI

from api.routes import detections, health, rules
from api.security import require_internal_token
from config import settings
from core.database.connection import close_mongo_connection, connect_to_mongo
from core.rules.rule_loader import RuleManager

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def expire_old_events() -> None:
    """
    The engine's copy of events expires after EVENT_RETENTION_DAYS, by a TTL index on when
    it was stored. Events stored before the index (no stored_at) are deleted by their own
    timestamp once they are that old.
    """
    from pymongo.errors import OperationFailure

    from core.database.connection import get_database
    from utils.time import utcnow

    events = get_database()["events"]
    seconds = settings.EVENT_RETENTION_DAYS * 86400
    existing = (await events.index_information()).get("stored_at_ttl")
    if existing and existing.get("expireAfterSeconds") != seconds:
        try:
            await events.drop_index("stored_at_ttl")
        except OperationFailure as e:
            if e.code != 27:  # already gone
                raise
    await events.create_index("stored_at", expireAfterSeconds=seconds, name="stored_at_ttl")
    cutoff = (utcnow() - timedelta(days=settings.EVENT_RETENTION_DAYS)).isoformat()
    result = await events.delete_many({"stored_at": {"$exists": False}, "timestamp": {"$lt": cutoff}})
    if result.deleted_count:
        logger.info(f"Deleted {result.deleted_count} events older than {settings.EVENT_RETENTION_DAYS} days")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    removed = await RuleManager().remove_untenanted_managed_rules()
    if removed:
        logger.info(f"Removed {removed} managed rules from before tenancy; the gateway sends them again")
    added = await RuleManager().load_predefined_rules()
    logger.info(f"Detection rules ready ({added} predefined rules added)")
    from core.detection.identity_detector import IdentityDetector

    await IdentityDetector().ensure_indexes()
    await expire_old_events()
    yield
    await close_mongo_connection()


app = FastAPI(
    title="UTDRS Core Engine",
    description="Core Detection Engine for the Unified Threat Detection and Response System",
    version="1.0.0",
    lifespan=lifespan,
)

# The engine is called by the API gateway, not by browsers, so no CORS is configured.
internal = [Depends(require_internal_token)]
app.include_router(health.router, tags=["health"])
app.include_router(rules.router, prefix="/rules", tags=["rules"], dependencies=internal)
app.include_router(detections.router, prefix="/detections", tags=["detections"], dependencies=internal)


@app.get("/")
async def root():
    return {"message": "Welcome to the UTDRS Core Engine API"}
