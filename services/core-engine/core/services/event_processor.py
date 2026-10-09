from typing import Dict, Any, Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# Lazy initialization of detection engine to avoid circular imports and early db access
_detection_engine = None

def get_detection_engine():
    global _detection_engine
    if _detection_engine is None:
        from core.detection.engine import DetectionEngine
        _detection_engine = DetectionEngine()
    return _detection_engine

async def process_event(event_data):
    try:
        logger.info(f"Processing event from source: {event_data.get('source', 'unknown')}")
        
        # Get detection engine when needed
        detection_engine = get_detection_engine()
        
        # Perform detection using the detection engine
        alert = await detection_engine.detect_threats(event_data)
        
        if alert:
            logger.info(f"Generated alert: {alert.title}")
            # In a real system, you might send the alert to the API Gateway or a notification service
            
        return alert
        
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return None