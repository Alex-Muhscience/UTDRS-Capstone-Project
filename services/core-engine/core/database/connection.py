from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import ConnectionFailure

from config import settings
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
    if db.client is None:
        raise ConnectionError("Database connection not established")
    return db.client[db.db_name]
