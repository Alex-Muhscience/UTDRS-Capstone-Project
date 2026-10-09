from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
from config import settings
from utils.logger import get_logger
import asyncio

logger = get_logger(__name__)

class Database:
    client: AsyncIOMotorClient = None
    db_name: str = settings.DB_NAME

db = Database()

async def connect_to_mongo():
    try:
        logger.info(f"Connecting to MongoDB at {settings.MONGODB_URI[:20]}...")
        db.client = AsyncIOMotorClient(settings.MONGODB_URI)
        # Validate connection
        await db.client.admin.command('ping')
        logger.info("Connected to MongoDB")
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error connecting to MongoDB: {str(e)}")
        raise

async def close_mongo_connection():
    if db.client:
        db.client.close()
        logger.info("Closed MongoDB connection")

# This is now synchronous - it returns the database client directly
def get_database():
    if db.client is None:
        logger.error("Database client is None, connection may have failed")
        raise ConnectionError("Database connection not established")
    return db.client[db.db_name]