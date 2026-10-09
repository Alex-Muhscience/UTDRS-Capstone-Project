from fastapi import APIRouter, FastAPI
import os
import logging
from core.detection.engine import DetectionEngine
from core.detection.yara_detector import YaraDetector, YaraRuleManager
from core.detection.correlation_detector import CorrelationDetector
from core.threat_intel.threat_intelligence import ThreatIntelligence
from core.database.connection import connect_to_mongo, close_mongo_connection
from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

"""
This module integrates all the enhanced components into the main application.
"""

async def setup_enhanced_detection():
    """
    Set up the enhanced detection components during application startup.
    """
    logger.info("Setting up enhanced detection components...")
    
    # Create necessary directories
    os.makedirs("rules/yara", exist_ok=True)
    os.makedirs("cache/threat_intel", exist_ok=True)
    
    # Initialize components
    try:
        # Initialize YARA rules
        yara_manager = YaraRuleManager()
        logger.info(f"Loaded {len(yara_manager.rules)} YARA rule files")
        
        # Initialize Threat Intelligence feed
        ti = ThreatIntelligence()
        # Start background task to update OSINT feeds
        import asyncio
        asyncio.create_task(ti.update_osint_feeds())
        logger.info("Started Threat Intelligence OSINT feed updates")
        
        # Initialize Correlation Detector and rules
        correlation_detector = CorrelationDetector()
        logger.info(f"Loaded {len(correlation_detector.rules)} correlation rules")
        
        # Initialize main detection engine
        detection_engine = DetectionEngine()
        logger.info("Enhanced Detection Engine initialized successfully")
        
        return True
    except Exception as e:
        logger.error(f"Error setting up enhanced detection: {str(e)}")
        return False

def create_enhanced_api_routes(app: FastAPI):
    """
    Create additional API routes for enhanced functionality.
    
    Args:
        app: FastAPI application to add routes to
    """
    # Create router for YARA rules
    yara_router = APIRouter(prefix="/yara", tags=["yara"])
    
    @yara_router.get("/")
    async def list_yara_rules():
        """List all YARA rules."""
        yara_manager = YaraRuleManager()
        rules = yara_manager.get_rules()
        return {"rules": rules}
    
    @yara_router.post("/")
    async def add_yara_rule(rule_content: str, category: str = "custom", filename: str = None):
        """Add a new YARA rule."""
        yara_manager = YaraRuleManager()
        success = yara_manager.add_rule(rule_content, category, filename)
        return {"success": success}
    
    @yara_router.delete("/{rule_key}")
    async def delete_yara_rule(rule_key: str):
        """Delete a YARA rule."""
        yara_manager = YaraRuleManager()
        success = yara_manager.remove_rule(rule_key)
        return {"success": success}
    
    # Create router for Threat Intelligence
    ti_router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])
    
    @ti_router.get("/check")
    async def check_indicator(indicator: str, type: str = None):
        """Check an indicator against threat intelligence sources."""
        ti = ThreatIntelligence()
        result = await ti.check_indicator(indicator, type)
        return result
    
    # Create router for correlations
    correlation_router = APIRouter(prefix="/correlations", tags=["correlations"])
    
    @correlation_router.get("/")
    async def get_correlations(time_window: int = 60):
        """Get current correlations."""
        correlation_detector = CorrelationDetector()
        correlations = await correlation_detector.correlate_events(time_window)
        return {"correlations": correlations}
    
    # Add all routers to app
    app.include_router(yara_router)
    app.include_router(ti_router)
    app.include_router(correlation_router)
    
    # Update existing detection routes
    detection_router = APIRouter(prefix="/detections", tags=["detections"])
    
    @detection_router.get("/summary")
    async def get_threat_summary():
        """Get a summary of current threat activity."""
        detection_engine = DetectionEngine()
        summary = await detection_engine.get_threat_summary()
        return summary
    
    @detection_router.post("/enrich/{alert_id}")
    async def enrich_alert(alert_id: str):
        """Enrich an alert with additional context."""
        detection_engine = DetectionEngine()
        enriched_alert = await detection_engine.enrich_alert(alert_id)
        if not enriched_alert:
            return {"success": False, "message": "Alert not found"}
        return {"success": True, "alert": enriched_alert}
    
    app.include_router(detection_router)
    
    logger.info("Enhanced API routes created successfully")

def update_app_py():
    """
    Code to update app.py to include the enhanced components.
    This is just a reference - actual implementation would modify app.py.
    """
    # Code snippet for updating app.py:
    """
    from fastapi import FastAPI
    from main_integration import setup_enhanced_detection, create_enhanced_api_routes
    
    app = FastAPI(
        title="UTDRS Core Engine",
        description="Enhanced Core Detection Engine for the Unified Threat Detection and Response System",
        version="2.0.0",
    )
    
    # Database events
    app.add_event_handler("startup", connect_to_mongo)
    app.add_event_handler("shutdown", close_mongo_connection)
    
    # Add setup for enhanced detection
    app.add_event_handler("startup", setup_enhanced_detection)
    
    # Include API routes
    app.include_router(health.router, tags=["health"])
    app.include_router(rules.router, prefix="/rules", tags=["rules"])
    
    # Create enhanced API routes
    create_enhanced_api_routes(app)
    
    # Include detection routes after DB is connected
    @app.on_event("startup")
    async def setup_detection_routes():
        from api.routes import detections
        app.include_router(detections.router, prefix="/detections", tags=["detections"])
        logger.info("Detection routes initialized")
    
    @app.get("/")
    async def root():
        return {"message": "Welcome to the Enhanced UTDRS Core Engine API"}
    """
    
def update_requirements_txt():
    """
    Update the requirements.txt file to include new dependencies.
    Again, this is a reference - actual implementation would modify the file.
    """
    # New requirements to add:
    """
    yara-python==4.2.0
    aiohttp==3.8.4
    scipy>=1.7.0
    ipaddress>=1.0.23
    """
    
if __name__ == "__main__":
    # This would be run to update the app configuration
    update_app_py()
    update_requirements_txt()
    print("Integration code generated. Update the actual files as needed.")