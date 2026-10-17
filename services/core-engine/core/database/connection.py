from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import ConnectionFailure

from config import settings
from core.tenancy import TenantDatabase
from utils.logger import get_logger

logger = get_logger(__name__)


class Database:
    client: AsyncMongoClient | None = None
    db_name: str = settings.DB_NAME


db = Database()


async def connect_to_mongo():
    try:
        logger.info("Connecting to MongoDB")
        db.client = AsyncMongoClient(settings.MONGODB_URI)
        # Validate connection
        await db.client.admin.command("ping")
        logger.info("Connected to MongoDB")
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise


async def close_mongo_connection():
    if db.client:
        await db.client.close()
        db.client = None
        logger.info("Closed MongoDB connection")


def get_database() -> AsyncDatabase:
    """The engine's database, showing only the current tenant's events and alerts while one is set (core.tenancy)."""
    if db.client is None:
        raise ConnectionError("Database connection not established")
    return TenantDatabase(db.client[db.db_name])
