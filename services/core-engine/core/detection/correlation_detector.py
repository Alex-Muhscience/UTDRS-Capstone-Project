from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
import uuid
import json
import hashlib
from utils.logger import get_logger
from core.database.connection import get_database

logger = get_logger(__name__)

class CorrelationRule:
    """Base class for correlation rules."""
    
    def __init__(self, name, description, severity="medium", threshold=1, time_window=60):
        """
        Initialize the correlation rule.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Alert severity if rule matches (critical, high, medium, low)
            threshold: Number of events needed to trigger the rule
            time_window: Time window in minutes for correlation
        """
        self.name = name
        self.description = description
        self.severity = severity
        self.threshold = threshold
        self.time_window = time_window
        
    async def matches(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check if events match this correlation rule.
        
        Args:
            events: List of events to correlate
            
        Returns:
            True if the rule matches, False otherwise
        """
        # Base implementation, should be overridden
        return len(events) >= self.threshold
        
    def get_rule_info(self) -> Dict[str, Any]:
        """Get information about this rule."""
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "threshold": self.threshold,
            "time_window": self.time_window
        }
        
    def get_correlation_id(self, events: List[Dict[str, Any]]) -> str:
        """
        Generate a correlation ID for a group of events.
        
        Args:
            events: List of events in the correlation
            
        Returns:
            Correlation ID string
        """
        # Default implementation uses a hash of event IDs
        event_ids = sorted([event.get('id', str(uuid.uuid4())) for event in events])
        return hashlib.md5(json.dumps(event_ids).encode()).hexdigest()


class SequenceCorrelationRule(CorrelationRule):
    """Rule that correlates a sequence of specific event types."""
    
    def __init__(self, name, description, sequence, severity="medium", time_window=60):
        """
        Initialize a sequence correlation rule.
        
        Args:
            name: Rule name
            description: Rule description
            sequence: List of event type dictionaries that must occur in order
                      Each dict should have an 'event_type' and optional additional filters
            severity: Alert severity if rule matches
            time_window: Time window in minutes for correlation
        """
        super().__init__(name, description, severity, len(sequence), time_window)
        self.sequence = sequence
        
    async def matches(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check if events match the sequence.
        
        Args:
            events: List of events to correlate
            
        Returns:
            True if the sequence matches, False otherwise
        """
        if len(events) < len(self.sequence):
            return False
            
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.get('timestamp', ''))
        
        # Try to find a matching sequence
        sequence_index = 0
        for event in sorted_events:
            if self._event_matches_pattern(event, self.sequence[sequence_index]):
                sequence_index += 1
                if sequence_index >= len(self.sequence):
                    return True
                    
        return False
        
    def _event_matches_pattern(self, event: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """
        Check if an event matches a pattern.
        
        Args:
            event: Event to check
            pattern: Pattern to match against
            
        Returns:
            True if the event matches the pattern, False otherwise
        """
        # Check event type
        if event.get('event_type') != pattern.get('event_type'):
            return False
            
        # Check additional filters
        for key, value in pattern.items():
            if key == 'event_type':
                continue
                
            # Handle nested keys (using dot notation)
            if '.' in key:
                parts = key.split('.')
                event_value = event
                for part in parts:
                    if not isinstance(event_value, dict) or part not in event_value:
                        return False
                    event_value = event_value[part]
                    
                if event_value != value:
                    return False
            elif key not in event or event[key] != value:
                return False
                
        return True


class ThresholdCorrelationRule(CorrelationRule):
    """Rule that correlates events based on a threshold within a time window."""
    
    def __init__(self, name, description, filters, threshold=5, severity="medium", time_window=60, group_by=None):
        """
        Initialize a threshold correlation rule.
        
        Args:
            name: Rule name
            description: Rule description
            filters: Dictionary of filters that events must match
            threshold: Number of matching events required to trigger
            severity: Alert severity if rule matches
            time_window: Time window in minutes for correlation
            group_by: Optional field to group events by
        """
        super().__init__(name, description, severity, threshold, time_window)
        self.filters = filters
        self.group_by = group_by
        
    async def matches(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check if events meet the threshold within the time window.
        
        Args:
            events: List of events to correlate
            
        Returns:
            True if the threshold is met, False otherwise
        """
        # Filter events that match the pattern
        matching_events = [e for e in events if self._event_matches_filters(e)]
        
        if not matching_events:
            return False
            
        # If group_by is specified, group events
        if self.group_by:
            groups = {}
            for event in matching_events:
                # Handle nested group_by fields
                if '.' in self.group_by:
                    parts = self.group_by.split('.')
                    group_value = event
                    for part in parts:
                        if not isinstance(group_value, dict) or part not in group_value:
                            group_value = None
                            break
                        group_value = group_value[part]
                else:
                    group_value = event.get(self.group_by)
                    
                if group_value is not None:
                    group_key = str(group_value)
                    if group_key not in groups:
                        groups[group_key] = []
                    groups[group_key].append(event)
                    
            # Check if any group meets the threshold
            return any(len(group) >= self.threshold for group in groups.values())
        else:
            # Just check if total matching events meet the threshold
            return len(matching_events) >= self.threshold
            
    def _event_matches_filters(self, event: Dict[str, Any]) -> bool:
        """
        Check if an event matches the filters.
        
        Args:
            event: Event to check
            
        Returns:
            True if the event matches all filters, False otherwise
        """
        for key, value in self.filters.items():
            # Handle nested keys (using dot notation)
            if '.' in key:
                parts = key.split('.')
                event_value = event
                for part in parts:
                    if not isinstance(event_value, dict) or part not in event_value:
                        return False
                    event_value = event_value[part]
                    
                if event_value != value:
                    return False
            elif key not in event or event[key] != value:
                return False
                
        return True
        
    def get_correlation_id(self, events: List[Dict[str, Any]]) -> str:
        """
        Generate a correlation ID for a threshold rule.
        
        Args:
            events: List of events in the correlation
            
        Returns:
            Correlation ID string
        """
        if self.group_by:
            # For grouped correlations, include the group values in the ID
            group_values = set()
            for event in events:
                if '.' in self.group_by:
                    parts = self.group_by.split('.')
                    group_value = event
                    for part in parts:
                        if not isinstance(group_value, dict) or part not in group_value:
                            group_value = None
                            break
                        group_value = group_value[part]
                else:
                    group_value = event.get(self.group_by)
                    
                if group_value is not None:
                    group_values.add(str(group_value))
                    
            group_str = "+".join(sorted(group_values))
            return f"{self.name}_{group_str}"
        else:
            # For ungrouped, use the rule name and time window
            timestamp = events[0].get('timestamp', datetime.utcnow().isoformat())
            return f"{self.name}_{timestamp}"


class NetworkCorrelationRule(CorrelationRule):
    """Rule that correlates network events based on IP relationships."""
    
    def __init__(self, name, description, severity="medium", min_hosts=3, time_window=60):
        """
        Initialize a network correlation rule.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Alert severity if rule matches
            min_hosts: Minimum number of connected hosts required
            time_window: Time window in minutes for correlation
        """
        super().__init__(name, description, severity, min_hosts, time_window)
        self.min_hosts = min_hosts
        
    async def matches(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check if events show network relationships.
        
        Args:
            events: List of events to correlate
            
        Returns:
            True if network relationships are found, False otherwise
        """
        # Only look at network events
        network_events = [e for e in events if e.get('event_type', '').startswith('network')]
        
        if len(network_events) < self.min_hosts:
            return False
            
        # Build a graph of IP connections
        connections = set()
        for event in network_events:
            src_ip = event.get('data', {}).get('src_ip')
            dst_ip = event.get('data', {}).get('dst_ip')
            
            if src_ip and dst_ip:
                connections.add((src_ip, dst_ip))
                
        # Get all unique IPs
        all_ips = set()
        for src, dst in connections:
            all_ips.add(src)
            all_ips.add(dst)
            
        # Check if we have enough connected hosts
        return len(all_ips) >= self.min_hosts


class HeuristicCorrelationRule(CorrelationRule):
    """Rule that uses heuristics to correlate seemingly unrelated events."""
    
    def __init__(self, name, description, severity="medium", time_window=60):
        """
        Initialize a heuristic correlation rule.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Alert severity if rule matches
            time_window: Time window in minutes for correlation
        """
        super().__init__(name, description, severity, 2, time_window)
        
    async def matches(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check if events show suspicious patterns using heuristics.
        
        Args:
            events: List of events to correlate
            
        Returns:
            True if suspicious patterns are found, False otherwise
        """
        # Different heuristic correlations to check
        heuristics = [
            self._check_auth_file_access_correlation,
            self._check_network_process_correlation,
            self._check_lateral_movement_correlation
        ]
        
        # Run all heuristics
        for heuristic in heuristics:
            if heuristic(events):
                return True
                
        return False
        
    def _check_auth_file_access_correlation(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check for authentication followed by sensitive file access.
        
        Args:
            events: List of events to check
            
        Returns:
            True if correlation is found, False otherwise
        """
        # Find authentication events
        auth_events = [e for e in events if e.get('event_type') == 'authentication']
        
        # Find file access events
        file_events = [e for e in events if e.get('event_type') == 'file']
        
        if not auth_events or not file_events:
            return False
            
        # Check for auth events followed by sensitive file access
        for auth_event in auth_events:
            auth_time = datetime.fromisoformat(auth_event.get('timestamp', ''))
            user_id = auth_event.get('data', {}).get('user_id')
            
            if not user_id:
                continue
                
            for file_event in file_events:
                file_time = datetime.fromisoformat(file_event.get('timestamp', ''))
                file_user = file_event.get('data', {}).get('user_id')
                filepath = file_event.get('data', {}).get('filepath', '')
                
                # Check if auth preceded file access
                if user_id == file_user and auth_time < file_time:
                    # Check if access to sensitive files
                    sensitive_paths = ['/etc', '/var/log', '/.ssh', '/root', 'C:\\Windows\\']
                    if any(path in filepath for path in sensitive_paths):
                        return True
                        
        return False
        
    def _check_network_process_correlation(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check for suspicious process followed by network connection.
        
        Args:
            events: List of events to check
            
        Returns:
            True if correlation is found, False otherwise
        """
        # Find process events
        process_events = [e for e in events if e.get('event_type') == 'process']
        
        # Find network events
        network_events = [e for e in events if e.get('event_type') == 'network']
        
        if not process_events or not network_events:
            return False
            
        # Check for suspicious process followed by network connection
        for process_event in process_events:
            process_time = datetime.fromisoformat(process_event.get('timestamp', ''))
            process_name = process_event.get('data', {}).get('process_name', '').lower()
            host = process_event.get('source', '')
            
            # Check if suspicious process
            suspicious_processes = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe']
            if not any(proc in process_name for proc in suspicious_processes):
                continue
                
            for network_event in network_events:
                network_time = datetime.fromisoformat(network_event.get('timestamp', ''))
                network_host = network_event.get('source', '')
                
                # Check if process preceded network and same host
                if host == network_host and process_time < network_time:
                    # Check if connection to unusual port
                    dst_port = network_event.get('data', {}).get('dst_port', 0)
                    unusual_ports = [4444, 8080, 1337, 31337, 6666, 8888]
                    
                    if dst_port in unusual_ports:
                        return True
                        
        return False
        
    def _check_lateral_movement_correlation(self, events: List[Dict[str, Any]]) -> bool:
        """
        Check for potential lateral movement across hosts.
        
        Args:
            events: List of events to check
            
        Returns:
            True if correlation is found, False otherwise
        """
        # Get authentication events
        auth_events = [e for e in events if e.get('event_type') == 'authentication']
        
        if len(auth_events) < 2:
            return False
            
        # Sort by timestamp
        sorted_auths = sorted(auth_events, key=lambda e: e.get('timestamp', ''))
        
        # Check for same user authenticating to different hosts in sequence
        users_hosts = {}
        
        for auth in sorted_auths:
            user = auth.get('data', {}).get('user_id')
            host = auth.get('source', '')
            
            if not user or not host:
                continue
                
            if user not in users_hosts:
                users_hosts[user] = [host]
            elif host not in users_hosts[user]:
                users_hosts[user].append(host)
                
        # Check if any user authenticated to multiple hosts
        return any(len(hosts) >= 2 for hosts in users_hosts.values())


class CorrelationDetector:
    """
    Detector that correlates multiple events to identify complex attack patterns.
    """
    
    def __init__(self):
        """Initialize the correlation detector."""
        self.db = get_database()
        self.rules = []
        self.load_rules()
        
    def load_rules(self):
        """Load correlation rules."""
        # Add sequence correlation rules
        self.rules.append(SequenceCorrelationRule(
            name="Authentication Brute Force Followed by Success",
            description="Multiple failed authentications followed by successful authentication",
            sequence=[
                {"event_type": "authentication", "data.status": "failed"},
                {"event_type": "authentication", "data.status": "failed"},
                {"event_type": "authentication", "data.status": "failed"},
                {"event_type": "authentication", "data.status": "success"}
            ],
            severity="high",
            time_window=30
        ))
        
        self.rules.append(SequenceCorrelationRule(
            name="Reconnaissance Followed by Exploitation",
            description="Network scanning followed by exploitation attempt",
            sequence=[
                {"event_type": "network", "data.operation": "scan"},
                {"event_type": "network", "data.operation": "connect"}
            ],
            severity="high",
            time_window=60
        ))
        
        # Add threshold correlation rules
        self.rules.append(ThresholdCorrelationRule(
            name="Multiple Failed Logins",
            description="Multiple failed login attempts",
            filters={"event_type": "authentication", "data.status": "failed"},
            threshold=5,
            severity="medium",
            time_window=10,
            group_by="data.user_id"
        ))
        
        self.rules.append(ThresholdCorrelationRule(
            name="Mass File Operations",
            description="Large number of file operations in short time",
            filters={"event_type": "file"},
            threshold=20,
            severity="high",
            time_window=5,
            group_by="source"
        ))
        
        # Add network correlation rules
        self.rules.append(NetworkCorrelationRule(
            name="Multiple Host Connections",
            description="Connections between multiple hosts in short time",
            severity="medium",
            min_hosts=3,
            time_window=30
        ))
        
        # Add heuristic correlation rule
        self.rules.append(HeuristicCorrelationRule(
            name="Suspicious Activity Chain",
            description="Heuristic detection of suspicious activity patterns",
            severity="high",
            time_window=60
        ))
        
    async def correlate_events(self, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Correlate recent events to identify related security incidents.
        
        Args:
            time_window_minutes: Time window for correlation in minutes
            
        Returns:
            List of correlation results (potential security incidents)
        """
        # Get recent events
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        recent_events = await self.db.events.find({
            "timestamp": {"$gte": time_threshold.isoformat()}
        }).to_list(length=10000)
        
        if not recent_events:
            return []
            
        logger.info(f"Correlating {len(recent_events)} events from the past {time_window_minutes} minutes")
        
        correlation_results = []
        
        # Apply each correlation rule
        for rule in self.rules:
            rule_time_window = timedelta(minutes=rule.time_window)
            
            # Group events by time windows
            for event in recent_events:
                event_time = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
                window_start = event_time - rule_time_window
                
                # Get events in this time window
                window_events = [
                    e for e in recent_events
                    if datetime.fromisoformat(e.get('timestamp', '')) >= window_start
                    and datetime.fromisoformat(e.get('timestamp', '')) <= event_time
                ]
                
                # Skip if not enough events
                if len(window_events) < rule.threshold:
                    continue
                    
                # Check if rule matches
                if await rule.matches(window_events):
                    # Create correlation result
                    correlation_id = rule.get_correlation_id(window_events)
                    
                    # Check if we already have this correlation
                    if any(r.get('correlation_id') == correlation_id for r in correlation_results):
                        continue
                        
                    # Sort events by timestamp
                    sorted_events = sorted(
                        window_events,
                        key=lambda e: e.get('timestamp', '')
                    )
                    
                    correlation_result = {
                        "correlation_id": correlation_id,
                        "rule_name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "event_count": len(window_events),
                        "start_time": sorted_events[0].get('timestamp'),
                        "end_time": sorted_events[-1].get('timestamp'),
                        "sources": list(set(e.get('source', '') for e in window_events)),
                        "event_types": list(set(e.get('event_type', '') for e in window_events)),
                        "event_ids": [e.get('id', '') for e in sorted_events],
                        "detection_type": "correlation"
                    }
                    
                    # Add MITRE ATT&CK mapping based on event types
                    mitre_tactics, mitre_techniques = self._get_mitre_mapping(window_events)
                    
                    if mitre_tactics:
                        correlation_result["mitre_tactics"] = mitre_tactics
                        
                    if mitre_techniques:
                        correlation_result["mitre_techniques"] = mitre_techniques
                        
                    correlation_results.append(correlation_result)
                    
        # Deduplicate results by correlation ID
        unique_results = {}
        for result in correlation_results:
            correlation_id = result.get('correlation_id')
            if correlation_id not in unique_results or result.get('severity') == 'critical':
                unique_results[correlation_id] = result
                
        return list(unique_results.values())
    
    def _get_mitre_mapping(self, events: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
        """
        Get MITRE ATT&CK tactics and techniques based on event types.
        
        Args:
            events: List of events
            
        Returns:
            Tuple of (tactics, techniques)
        """
        tactics = set()
        techniques = set()
        
        # Look for existing MITRE mappings in events
        for event in events:
            details = event.get('details', {})
            
            if 'mitre_tactics' in details:
                for tactic in details['mitre_tactics']:
                    tactics.add(tactic)
                    
            if 'mitre_techniques' in details:
                for technique in details['mitre_techniques']:
                    techniques.add(technique)
                    
        # If no mappings found, infer from event types
        if not tactics and not techniques:
            event_types = set(e.get('event_type', '') for e in events)
            
            if 'authentication' in event_types:
                tactics.add("TA0006")  # Credential Access
                techniques.add("T1110")  # Brute Force
                
            if 'file' in event_types:
                tactics.add("TA0009")  # Collection
                techniques.add("T1005")  # Data from Local System
                
            if 'network' in event_types:
                tactics.add("TA0011")  # Command and Control
                techniques.add("T1071")  # Application Layer Protocol
                
            if 'process' in event_types:
                tactics.add("TA0002")  # Execution
                techniques.add("T1059")  # Command and Scripting Interpreter
                
        return list(tactics), list(techniques)
        
    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a new event and check for correlations.
        
        Args:
            event: The event to process
            
        Returns:
            Correlation detection result if found, None otherwise
        """
        # Store the event
        await self.db.events.insert_one(event)
        
        # Correlate recent events
        correlations = await self.correlate_events()
        
        # Find correlations that include this event
        event_id = event.get('id')
        matching_correlations = [
            c for c in correlations
            if event_id in c.get('event_ids', [])
        ]
        
        if matching_correlations:
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            matching_correlations.sort(
                key=lambda c: severity_order.get(c.get('severity', 'medium'), 2)
            )
            
            # Return the highest severity correlation
            result = matching_correlations[0]
            
            return {
                "name": result['rule_name'],
                "description": result['description'],
                "severity": result['severity'],
                "detection_type": "correlation",
                "correlation_id": result['correlation_id'],
                "confidence": 0.8,  # Correlations have good confidence
                "details": {
                    "event_count": result['event_count'],
                    "start_time": result['start_time'],
                    "end_time": result['end_time'],
                    "sources": result['sources'],
                    "event_types": result['event_types']
                },
                "event_ids": result['event_ids'],
                "mitre_tactics": result.get('mitre_tactics', []),
                "mitre_techniques": result.get('mitre_techniques', [])
            }
            
        return None