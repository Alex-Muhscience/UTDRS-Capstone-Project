"""
Risk scoring module for UTDRS core engine.
Calculates risk scores for alerts and assets based on various factors.
"""
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from utils.logger import get_logger

logger = get_logger(__name__)

class RiskScorer:
    """
    Calculates risk scores for alerts and assets based on threat severity, 
    asset criticality, and other contextual factors.
    """
    
    def __init__(self):
        """Initialize the risk scorer."""
        # Configure risk scoring parameters
        self.severity_weights = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25,
            'info': 10
        }
        
        self.detection_type_weights = {
            'signature': 1.0,  # High confidence
            'ml': 0.9,         # Good confidence
            'anomaly': 0.8     # Lower confidence
        }
        
        self.asset_criticality = {
            'critical': 2.0,   # Critical business systems
            'high': 1.5,       # Important systems
            'medium': 1.0,     # Standard systems
            'low': 0.5         # Low-value systems
        }
        
        self.time_decay_factor = 0.9  # Score degrades over time
        
    def calculate_alert_risk(self, alert: Dict[str, Any]) -> float:
        """
        Calculate a risk score for an alert.
        
        Args:
            alert: The alert to calculate risk for
            
        Returns:
            Risk score from 0-100
        """
        # Extract relevant fields
        severity = alert.get('severity', 'medium')
        detection_type = alert.get('detection_type', 'signature')
        confidence = alert.get('details', {}).get('detection', {}).get('confidence', 0.8)
        
        # Get base score from severity
        base_score = self.severity_weights.get(severity, 50)
        
        # Apply detection type weighting
        detection_weight = self.detection_type_weights.get(detection_type, 0.8)
        
        # Apply confidence factor
        weighted_score = base_score * detection_weight * confidence
        
        # Boost for certain tags
        tags = alert.get('tags', [])
        boost = 0
        
        if isinstance(tags, list):
            for tag in tags:
                if tag in ['ransomware', 'data-exfiltration', 'lateral-movement']:
                    boost += 10
                elif tag in ['command-and-control', 'privilege-escalation']:
                    boost += 5
                    
        # Apply time decay for older alerts
        created_at = alert.get('created_at')
        if created_at:
            # Calculate time since creation
            try:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                
                hours_old = (datetime.utcnow() - created_at).total_seconds() / 3600
                time_factor = self.time_decay_factor ** min(hours_old / 24, 7)  # Cap at 7 days
                weighted_score *= time_factor
            except (ValueError, TypeError) as e:
                logger.warning(f"Error calculating time decay: {str(e)}")
        
        # Calculate final score (cap at 100)
        final_score = min(100, weighted_score + boost)
        
        return final_score
    
    def calculate_asset_risk(self, asset_id: str, alerts: List[Dict[str, Any]], 
                             asset_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate a risk score for an asset based on its alerts and metadata.
        
        Args:
            asset_id: The ID of the asset
            alerts: List of alerts related to the asset
            asset_metadata: Optional asset metadata
            
        Returns:
            Dictionary with risk information
        """
        # Get asset criticality
        criticality = 'medium'
        if asset_metadata:
            criticality = asset_metadata.get('criticality', 'medium')
            
        criticality_multiplier = self.asset_criticality.get(criticality, 1.0)
        
        # Calculate risk from alerts
        if not alerts:
            return {
                'asset_id': asset_id,
                'risk_score': 0,
                'risk_level': 'low',
                'criticality': criticality,
                'alert_count': 0,
                'latest_alert': None
            }
            
        # Calculate individual alert risk scores
        alert_risks = [self.calculate_alert_risk(alert) for alert in alerts]
        
        # Use the highest risk score as the base (risk doesn't simply add up)
        highest_risk = max(alert_risks)
        
        # Apply diminishing returns formula for multiple alerts
        # Additional risk from multiple alerts follows a logarithmic curve
        import math
        alert_count = len(alerts)
        multiple_alerts_factor = 1 + (math.log10(alert_count) / 2) if alert_count > 1 else 1
        
        # Calculate final risk score
        asset_risk = min(100, highest_risk * criticality_multiplier * multiple_alerts_factor)
        
        # Determine risk level
        risk_level = 'critical' if asset_risk >= 80 else 'high' if asset_risk >= 60 else 'medium' if asset_risk >= 40 else 'low'
        
        # Get latest alert
        latest_alert = max(alerts, key=lambda a: a.get('created_at', datetime.min))
        
        return {
            'asset_id': asset_id,
            'risk_score': asset_risk,
            'risk_level': risk_level,
            'criticality': criticality,
            'alert_count': alert_count,
            'latest_alert': latest_alert.get('_id')
        }
    
    def calculate_organizational_risk(self, assets_risk: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall organizational risk based on asset risk scores.
        
        Args:
            assets_risk: List of asset risk information
            
        Returns:
            Dictionary with organizational risk metrics
        """
        if not assets_risk:
            return {
                'overall_risk_score': 0,
                'risk_level': 'low',
                'critical_assets_at_risk': 0,
                'high_risk_assets': 0,
                'medium_risk_assets': 0,
                'low_risk_assets': 0
            }
            
        # Count assets by risk level
        risk_levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        critical_assets_at_risk = 0
        
        for asset in assets_risk:
            risk_level = asset.get('risk_level', 'low')
            risk_levels[risk_level] += 1
            
            # Count critical assets with high or critical risk
            if asset.get('criticality') == 'critical' and risk_level in ['critical', 'high']:
                critical_assets_at_risk += 1
                
        # Calculate weighted average risk score
        total_risk = sum(asset.get('risk_score', 0) for asset in assets_risk)
        avg_risk = total_risk / len(assets_risk) if assets_risk else 0
        
        # Apply weightings for critical/high risk assets
        weighted_risk = avg_risk * (1 + (risk_levels['critical'] * 0.2) + (risk_levels['high'] * 0.1))
        
        # Cap at 100
        overall_risk = min(100, weighted_risk)
        
        # Determine overall risk level
        overall_level = 'critical' if overall_risk >= 80 else 'high' if overall_risk >= 60 else 'medium' if overall_risk >= 40 else 'low'
        
        return {
            'overall_risk_score': overall_risk,
            'risk_level': overall_level,
            'critical_assets_at_risk': critical_assets_at_risk,
            'high_risk_assets': risk_levels['high'] + risk_levels['critical'],
            'medium_risk_assets': risk_levels['medium'],
            'low_risk_assets': risk_levels['low']
        }
    
    def prioritize_alerts(self, alerts: List[Dict[str, Any]], 
                          assets_metadata: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Prioritize alerts based on risk scores.
        
        Args:
            alerts: List of alerts to prioritize
            assets_metadata: Optional dict mapping asset IDs to their metadata
            
        Returns:
            List of alerts with added risk_score field, sorted by priority
        """
        enriched_alerts = []
        
        for alert in alerts:
            # Calculate basic risk score
            risk_score = self.calculate_alert_risk(alert)
            
            # Apply asset criticality if available
            asset_id = alert.get('asset_id')
            if asset_id and assets_metadata and asset_id in assets_metadata:
                criticality = assets_metadata[asset_id].get('criticality', 'medium')
                criticality_multiplier = self.asset_criticality.get(criticality, 1.0)
                risk_score = min(100, risk_score * criticality_multiplier)
                
            # Create enriched alert with risk score
            enriched_alert = alert.copy()
            enriched_alert['risk_score'] = risk_score
            enriched_alerts.append(enriched_alert)
            
        # Sort by risk score (descending)
        return sorted(enriched_alerts, key=lambda a: a.get('risk_score', 0), reverse=True)


class AssetRiskManager:
    """
    Manages risk assessment for assets in the organization.
    """
    
    def __init__(self, db):
        """
        Initialize the asset risk manager.
        
        Args:
            db: Database connection
        """
        self.db = db
        self.risk_scorer = RiskScorer()
        
    async def calculate_asset_risks(self, time_window_days: int = 7) -> List[Dict[str, Any]]:
        """
        Calculate risk scores for all assets based on recent alerts.
        
        Args:
            time_window_days: Number of days of alert history to consider
            
        Returns:
            List of asset risk information
        """
        # Get recent alerts grouped by asset
        from datetime import datetime, timedelta
        time_threshold = datetime.utcnow() - timedelta(days=time_window_days)
        
        # First, get distinct assets that have alerts
        assets_with_alerts = await self.db.alerts.distinct('asset_id', {
            'created_at': {'$gte': time_threshold}
        })
        
        # Get asset metadata
        assets_metadata = {}
        for asset_id in assets_with_alerts:
            if asset_id:
                asset = await self.db.assets.find_one({'_id': asset_id})
                if asset:
                    assets_metadata[asset_id] = asset
        
        # Calculate risk for each asset
        asset_risks = []
        
        for asset_id in assets_with_alerts:
            if asset_id:
                # Get all alerts for this asset
                alerts = await self.db.alerts.find({
                    'asset_id': asset_id,
                    'created_at': {'$gte': time_threshold}
                }).to_list(length=1000)
                
                # Calculate risk
                asset_metadata = assets_metadata.get(asset_id)
                asset_risk = self.risk_scorer.calculate_asset_risk(asset_id, alerts, asset_metadata)
                asset_risks.append(asset_risk)
        
        # Sort by risk score (descending)
        return sorted(asset_risks, key=lambda a: a.get('risk_score', 0), reverse=True)
    
    async def get_organizational_risk(self) -> Dict[str, Any]:
        """
        Calculate overall organizational risk.
        
        Returns:
            Dictionary with organizational risk metrics
        """
        # Calculate risk for all assets
        asset_risks = await self.calculate_asset_risks()
        
        # Calculate organizational risk
        org_risk = self.risk_scorer.calculate_organizational_risk(asset_risks)
        
        # Add timestamp
        org_risk['timestamp'] = datetime.utcnow().isoformat()
        
        # Store risk assessment in database for historical tracking
        await self.db.risk_assessments.insert_one(org_risk)
        
        return org_risk
    
    async def get_risk_history(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get historical risk scores.
        
        Args:
            days: Number of days of history to retrieve
            
        Returns:
            List of historical risk assessments
        """
        from datetime import datetime, timedelta
        time_threshold = datetime.utcnow() - timedelta(days=days)
        
        # Format for date aggregation
        date_format = {
            'year': {'$year': {'$dateFromString': {'dateString': '$timestamp'}}},
            'month': {'$month': {'$dateFromString': {'dateString': '$timestamp'}}},
            'day': {'$dayOfMonth': {'$dateFromString': {'dateString': '$timestamp'}}}
        }
        
        # Aggregate to get daily average
        pipeline = [
            {'$match': {'timestamp': {'$gte': time_threshold.isoformat()}}},
            {'$group': {
                '_id': date_format,
                'risk_score': {'$avg': '$overall_risk_score'},
                'risk_level': {'$last': '$risk_level'},
                'critical_assets_at_risk': {'$avg': '$critical_assets_at_risk'},
                'high_risk_assets': {'$avg': '$high_risk_assets'}
            }},
            {'$sort': {'_id.year': 1, '_id.month': 1, '_id.day': 1}}
        ]
        
        risk_history = await self.db.risk_assessments.aggregate(pipeline).to_list(length=days)
        
        # Format the results
        formatted_history = []
        for entry in risk_history:
            date_parts = entry.get('_id', {})
            if all(k in date_parts for k in ['year', 'month', 'day']):
                date_str = f"{date_parts['year']}-{date_parts['month']:02d}-{date_parts['day']:02d}"
                
                formatted_history.append({
                    'date': date_str,
                    'risk_score': entry.get('risk_score', 0),
                    'risk_level': entry.get('risk_level', 'low'),
                    'critical_assets_at_risk': entry.get('critical_assets_at_risk', 0),
                    'high_risk_assets': entry.get('high_risk_assets', 0)
                })
                
        return formatted_history