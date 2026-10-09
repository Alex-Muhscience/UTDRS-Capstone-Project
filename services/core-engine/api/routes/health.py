from fastapi import APIRouter, Depends
from core.database.connection import get_database

router = APIRouter()

@router.get("/health")
async def health_check():
    '''Health check endpoint to verify API and database are working.'''
    return {
        "status": "ok",
        "service": "core-engine"
    }

@router.get("/health/db")
async def database_health_check():
    '''Check database connection health.'''
    db = get_database()
    try:
        # Execute simple command to check DB connection
        await db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        return {"status": "error", "database": "disconnected", "detail": str(e)}
