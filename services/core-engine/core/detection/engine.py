from typing import Dict, List, Any, Optional
import asyncio
from datetime import datetime
import logging
from core.database.repositories.alert_repository import AlertRepository
from core.rules.rule_loader import RuleManager
from core.detection.signature_detector import SignatureDetector
from core.detection.anomaly_detector import AnomalyDetector
from core.detection.ml_detector import MLDetector
from core.detection.yara_detector import YaraDetector
from core.detection.correlation_detector import CorrelationDetector
from core.threat_intel.threat_intelligence import ThreatIntelligenceDetector
from core.models.schema.alert import Alert, AlertCreate
from utils.logger import get_logger

logger = get_logger(__name__)

class DetectionEngine:
    """
    Enhanced core detection engine that orchestrates and prioritizes different detection methods.
    """
    
    def __init__(self):
        """Initialize the detection engine with its component detectors."""
        self.alert_repository = AlertRepository()
        self.rule_manager = RuleManager()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.ml_detector = MLDetector()
        self.yara_detector = YaraDetector()
        self.correlation_detector = CorrelationDetector()
        self.ti_detector = ThreatIntelligenceDetector()
        self.enable_threat_intel = True  # Set to False to disable TI lookups
        
    async def detect_threats(self, event: Dict[str, Any]) -> Optional[Alert]:
        """
        Analyze an event for threats using all available detection methods.
        
        Args:
            event: The event to analyze
            
        Returns:
            Alert object if a threat is detected, None otherwise
        """
        source = event.get('source', 'unknown')
        event_type = event.get('event_type', 'unknown')
        logger.info(f"Analyzing {event_type} event from {source}")
        
        # Assign a unique ID to the event if it doesn't have one
        if 'id' not in event:
            from uuid import uuid4
            event['id'] = str(uuid4())
            
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.utcnow().isoformat()
        
        # Run detection methods concurrently for better performance
        signature_task = asyncio.create_task(self._run_signature_detection(event))
        yara_task = asyncio.create_task(self._run_yara_detection(event))
        ml_task = asyncio.create_task(self._run_ml_detection(event))
        anomaly_task = asyncio.create_task(self._run_anomaly_detection(event))
        correlation_task = asyncio.create_task(self._run_correlation_detection(event))
        
        # Only run threat intel detection if enabled (can be rate limited or slow)
        if self.enable_threat_intel:
            ti_task = asyncio.create_task(self._run_threat_intel_detection(event))
        else:
            ti_task = asyncio.create_task(asyncio.sleep(0))  # Dummy task
            
        # Wait for all detections to complete
        results = await asyncio.gather(
            signature_task, yara_task, ml_task, anomaly_task, correlation_task, ti_task,
            return_exceptions=True
        )
        
        # Process any exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                detection_method = ["signature", "yara", "ml", "anomaly", "correlation", "threat_intel"][i]
                logger.error(f"Error in {detection_method} detection: {str(result)}")
                results[i] = None
                
        # Extract results
        signature_result, yara_result, ml_result, anomaly_result, correlation_result, ti_result = results
        
        # Process results in order of reliability/specificity
        priority_results = [
            (signature_result, "signature"),
            (yara_result, "yara"),
            (correlation_result, "correlation"),
            (ti_result, "threat_intel"),
            (ml_result, "ml"),
            (anomaly_result, "anomaly")
        ]
        
        # Return the first detection result that is not None
        for result, detector_type in priority_results:
            if result:
                logger.info(f"{detector_type.capitalize()} detection found threat: {result['name']}")
                return await self._create_alert(event, result)
                
        logger.info("No threats detected in event")
        return None
    
    async def _run_signature_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run signature-based detection on the event."""
        try:
            return await self.signature_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in signature detection: {str(e)}")
            return None
            
    async def _run_yara_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run YARA-based detection on the event."""
        try:
            # Only run YARA detection on file events or events with content
            if event.get('event_type') == 'file':
                file_path = event.get('data', {}).get('filepath')
                if file_path:
                    return await self.yara_detector.detect_file(file_path, event.get('data', {}))
            elif 'content' in event.get('data', {}):
                content = event.get('data', {}).get('content')
                if content:
                    return await self.yara_detector.detect_content(content, event.get('data', {}))
            return None
        except Exception as e:
            logger.error(f"Error in YARA detection: {str(e)}")
            return None
            
    async def _run_ml_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run ML-based detection on the event."""
        try:
            return await self.ml_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in ML detection: {str(e)}")
            return None
            
    async def _run_anomaly_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run anomaly detection on the event."""
        try:
            return await self.anomaly_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return None
            
    async def _run_correlation_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run correlation detection on the event."""
        try:
            return await self.correlation_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in correlation detection: {str(e)}")
            return None
            
    async def _run_threat_intel_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run threat intelligence detection on the event."""
        try:
            return await self.ti_detector.detect(event)
        except Exception as e:
            logger.error(f"Error in threat intelligence detection: {str(e)}")
            return None
        
    async def _create_alert(self, event: Dict[str, Any], detection_result: Dict[str, Any]) -> Alert:
        """
        Create an alert from a detection result.
        
        Args:
            event: The event that triggered the alert
            detection_result: The detection result with threat information
            
        Returns:
            The created Alert object
        """
        # Extract MITRE ATT&CK information if available
        mitre_tactics = detection_result.get('mitre_tactics', [])
        mitre_techniques = detection_result.get('mitre_techniques', [])
        
        # Calculate risk score based on severity and confidence
        risk_score = self._calculate_risk_score(detection_result)
        
        # Create alert data
        alert_data = AlertCreate(
            title=detection_result['name'],
            description=detection_result['description'],
            severity=detection_result['severity'],
            source=event.get('source', 'unknown'),
            event_ids=[event.get('id', 'unknown')],
            detection_type=detection_result['detection_type'],
            details={
                'event': event,
                'detection': detection_result,
                'mitre_tactics': mitre_tactics,
                'mitre_techniques': mitre_techniques,
                'risk_score': risk_score
            }
        )
        
        # For correlation alerts, include all related event IDs
        if detection_result['detection_type'] == 'correlation' and 'event_ids' in detection_result:
            alert_data.event_ids = detection_result['event_ids']
        
        # Store the alert in the database
        alert = await self.alert_repository.create_alert(alert_data)
        
        # In a full system, we would also:
        # 1. Send alert to notification system
        # 2. Trigger automated response actions
        # 3. Update risk scores for affected assets
        
        return alert
    
    def _calculate_risk_score(self, detection_result: Dict[str, Any]) -> float:
        """
        Calculate a risk score from 0-100 based on detection characteristics.
        
        Args:
            detection_result: The detection result with threat information
            
        Returns:
            Risk score from 0-100
        """
        # Base score from severity
        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30,
            'info': 10
        }
        
        base_score = severity_scores.get(detection_result.get('severity', 'medium'), 50)
        
        # Adjust based on confidence if available
        confidence = detection_result.get('confidence', 0.8)
        confidence_multiplier = confidence
        
        # Adjust based on detection type
        detection_type_multipliers = {
            'signature': 1.0,  # High reliability
            'yara': 1.0,       # High reliability
            'correlation': 0.9, # Good reliability
            'threat_intel': 0.9, # Good reliability
            'ml': 0.8,         # Medium reliability
            'anomaly': 0.7     # Lower reliability
        }
        
        type_multiplier = detection_type_multipliers.get(
            detection_result.get('detection_type', 'signature'), 
            0.8
        )
        
        # Boost score for certain detection types or tags
        boost = 0
        tags = detection_result.get('tags', [])
        
        if isinstance(tags, list):
            # High-priority threats
            if any(tag in tags for tag in ['ransomware', 'lateral-movement', 'data-exfiltration']):
                boost += 10
                
            # Medium-priority threats
            if any(tag in tags for tag in ['command-and-control', 'privilege-escalation', 'credential-access']):
                boost += 5
                
            # Persistent threats
            if any(tag in tags for tag in ['persistence', 'defense-evasion']):
                boost += 3
                
        # Boost for MITRE ATT&CK tactics associated with high-impact attacks
        high_impact_tactics = ['TA0040', 'TA0001', 'TA0006', 'TA0008', 'TA0010']
        mitre_tactics = detection_result.get('mitre_tactics', [])
        
        if any(tactic in mitre_tactics for tactic in high_impact_tactics):
            boost += 5
            
        # Calculate final score (capped at 100)
        risk_score = min(100, base_score * confidence_multiplier * type_multiplier + boost)
        
        return risk_score
        
    async def get_alerts(self, filters: Dict[str, Any], limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """
        Get alerts based on filters.
        
        Args:
            filters: Dictionary of filter criteria
            limit: Maximum number of alerts to return
            skip: Number of alerts to skip (for pagination)
            
        Returns:
            List of matching alerts
        """
        return await self.alert_repository.find_many(filters, limit, skip)
        
    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific alert by ID.
        
        Args:
            alert_id: The ID of the alert to retrieve
            
        Returns:
            The alert if found, None otherwise
        """
        return await self.alert_repository.find_by_id(alert_id)
        
    async def update_alert_status(self, alert_id: str, status: str, assigned_to: Optional[str] = None) -> Optional[Alert]:
        """
        Update the status of an alert.
        
        Args:
            alert_id: The ID of the alert to update
            status: The new status (open, in_progress, resolved, closed, false_positive)
            assigned_to: The user to assign the alert to
            
        Returns:
            The updated alert if found, None otherwise
        """
        return await self.alert_repository.update_alert_status(alert_id, status, assigned_to)
        
    async def get_threat_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current threat activity.
        
        Returns:
            Dictionary with threat summary statistics
        """
        # Get alert counts by severity
        from datetime import datetime, timedelta
        
        # Last 24 hours
        time_threshold = datetime.utcnow() - timedelta(hours=24)
        
        # Get total alert count
        total_alerts = await self.alert_repository.count({
            "created_at": {"$gte": time_threshold}
        })
        
        # Get count by severity
        severities = ['critical', 'high', 'medium', 'low', 'info']
        severity_counts = {}
        
        for severity in severities:
            count = await self.alert_repository.count({
                "severity": severity,
                "created_at": {"$gte": time_threshold}
            })
            severity_counts[severity] = count
            
        # Get count by detection type
        detection_types = ['signature', 'anomaly', 'ml', 'yara', 'correlation', 'threat_intel']
        detection_type_counts = {}
        
        for detection_type in detection_types:
            count = await self.alert_repository.count({
                "detection_type": detection_type,
                "created_at": {"$gte": time_threshold}
            })
            detection_type_counts[detection_type] = count
            
        # Get top sources
        pipeline = [
            {"$match": {"created_at": {"$gte": time_threshold}}},
            {"$group": {"_id": "$source", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        
        top_sources = await self.alert_repository.collection.aggregate(pipeline).to_list(length=5)
        
        # Get top MITRE techniques
        pipeline = [
            {"$match": {"created_at": {"$gte": time_threshold}}},
            {"$unwind": {"path": "$details.mitre_techniques", "preserveNullAndEmptyArrays": False}},
            {"$group": {"_id": "$details.mitre_techniques", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        
        top_techniques = await self.alert_repository.collection.aggregate(pipeline).to_list(length=5)
        
        # Get correlations count
        correlations_count = await self.alert_repository.count({
            "detection_type": "correlation",
            "created_at": {"$gte": time_threshold}
        })
        
        return {
            "total_alerts": total_alerts,
            "by_severity": severity_counts,
            "by_detection_type": detection_type_counts,
            "top_sources": top_sources,
            "top_techniques": top_techniques,
            "correlations_count": correlations_count,
            "time_period": "last_24_hours"
        }
        
    async def enrich_alert(self, alert_id: str) -> Optional[Alert]:
        """
        Enrich an existing alert with additional context.
        
        Args:
            alert_id: The ID of the alert to enrich
            
        Returns:
            The enriched alert if found, None otherwise
        """
        # Get the alert
        alert = await self.get_alert_by_id(alert_id)
        if not alert:
            return None
            
        # Get the original event(s)
        event_ids = alert.get('event_ids', [])
        if not event_ids:
            return alert
            
        # Get the first event (primary trigger)
        from core.database.connection import get_database
        db = get_database()
        event = await db.events.find_one({'id': event_ids[0]})
        
        if not event:
            return alert
            
        # Enrich with threat intelligence if applicable
        if self.enable_threat_intel and 'ti_enrichment' not in alert.get('details', {}):
            # Create TI detector if not already created
            if not hasattr(self, 'ti_detector'):
                from core.threat_intel.threat_intelligence import ThreatIntelligenceDetector
                self.ti_detector = ThreatIntelligenceDetector()
                
            # Enrich the event
            enriched_event = await self.ti_detector.ti_provider.enrich_event(event)
            
            # Update the alert with enriched data
            alert_details = alert.get('details', {})
            alert_details['ti_enrichment'] = enriched_event.get('ti_enrichment', {})
            
            # Update in database
            await self.alert_repository.update_one(alert_id, {'details': alert_details})
            
            # Get the updated alert
            return await self.get_alert_by_id(alert_id)
            
        # If already enriched, just return the alert
        return alert