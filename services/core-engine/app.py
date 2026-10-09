from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from api.routes import health, rules
from core.database.connection import connect_to_mongo, close_mongo_connection
from config import settings
import logging

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="UTDRS Core Engine",
    description="Core Detection Engine for the Unified Threat Detection and Response System",
    version="1.0.0",
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database events
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)

# Include API routes
app.include_router(health.router, tags=["health"])
app.include_router(rules.router, prefix="/rules", tags=["rules"])

# Import detections router AFTER database has been connected
@app.on_event("startup")
async def setup_detection_routes():
    from api.routes import detections
    app.include_router(detections.router, prefix="/detections", tags=["detections"])
    logger.info("Detection routes initialized")

@app.get("/")
async def root():
    return {"message": "Welcome to the UTDRS Core Engine API"}