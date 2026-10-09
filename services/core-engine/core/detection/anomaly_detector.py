from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import statistics
import numpy as np
from scipy import stats
import math
from utils.logger import get_logger
from core.database.connection import get_database

logger = get_logger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.db = get_database()
        self.baseline_window = 7  # Days to look back for baseline
        self.anomaly_threshold = 2.0  # Standard deviations from mean
        
        # Seasonality detection parameters
        self.hourly_patterns = {}  # Cache for hourly patterns
        self.daily_patterns = {}   # Cache for daily patterns
        self.last_cache_refresh = datetime.min  # Timestamp for cache refresh

    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect anomalies in the event by comparing with historical data patterns.
        
        Args:
            event: The event to analyze for anomalies
            
        Returns:
            Detection result dict if anomaly found, None otherwise
        """
        # Refresh pattern caches if needed (once per day)
        if datetime.utcnow() - self.last_cache_refresh > timedelta(days=1):
            await self._refresh_pattern_caches()
            
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        
        if not event_type or not source:
            logger.debug("Event missing type or source, skipping anomaly detection")
            return None
            
        # Different detection strategies based on event type
        if 'authentication' in event_type:
            return await self._detect_auth_anomalies(event)
        elif 'network' in event_type:
            return await self._detect_network_anomalies(event)
        elif 'file' in event_type:
            return await self._detect_file_anomalies(event)
        elif 'process' in event_type:
            return await self._detect_process_anomalies(event)
        else:
            # Default frequency-based detection
            return await self._detect_frequency_anomalies(event)
    
    async def _refresh_pattern_caches(self):
        """Refresh the hourly and daily pattern caches for common event types."""
        logger.info("Refreshing pattern caches for anomaly detection")
        
        # Define common event types to cache patterns for
        event_types = ['authentication', 'network', 'file', 'process']
        
        for event_type in event_types:
            # Get hourly patterns
            self.hourly_patterns[event_type] = await self._calculate_hourly_pattern(event_type)
            # Get daily patterns
            self.daily_patterns[event_type] = await self._calculate_daily_pattern(event_type)
        
        self.last_cache_refresh = datetime.utcnow()
        logger.info("Pattern caches refreshed successfully")
            
    async def _calculate_hourly_pattern(self, event_type: str) -> Dict[int, float]:
        """Calculate the normal hourly distribution of events for a given type."""
        # Aggregate events by hour for the baseline period
        now = datetime.utcnow()
        start_date = (now - timedelta(days=self.baseline_window)).isoformat()
        
        pipeline = [
            {'$match': {
                'event_type': event_type,
                'timestamp': {'$gte': start_date}
            }},
            {'$project': {
                'hour': {'$hour': {'$dateFromString': {'dateString': '$timestamp'}}}
            }},
            {'$group': {
                '_id': '$hour',
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id': 1}}
        ]
        
        result = await self.db.events.aggregate(pipeline).to_list(length=24)
        
        # Convert to hourly distribution
        hourly_counts = {i: 0 for i in range(24)}  # Initialize all hours with 0
        total_count = 0
        
        for item in result:
            hour = item['_id']
            count = item['count']
            hourly_counts[hour] = count
            total_count += count
            
        # Convert to percentages (normalized distribution)
        hourly_pattern = {}
        if total_count > 0:
            for hour, count in hourly_counts.items():
                hourly_pattern[hour] = count / total_count
                
        return hourly_pattern
        
    async def _calculate_daily_pattern(self, event_type: str) -> Dict[int, float]:
        """Calculate the normal daily distribution of events for a given type."""
        # Aggregate events by day of week for the baseline period
        now = datetime.utcnow()
        start_date = (now - timedelta(days=self.baseline_window * 2)).isoformat()
        
        pipeline = [
            {'$match': {
                'event_type': event_type,
                'timestamp': {'$gte': start_date}
            }},
            {'$project': {
                'dayOfWeek': {'$dayOfWeek': {'$dateFromString': {'dateString': '$timestamp'}}}
            }},
            {'$group': {
                '_id': '$dayOfWeek',
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id': 1}}
        ]
        
        result = await self.db.events.aggregate(pipeline).to_list(length=7)
        
        # Convert to daily distribution
        daily_counts = {i: 0 for i in range(1, 8)}  # 1=Sunday, 7=Saturday
        total_count = 0
        
        for item in result:
            day = item['_id']
            count = item['count']
            daily_counts[day] = count
            total_count += count
            
        # Convert to percentages (normalized distribution)
        daily_pattern = {}
        if total_count > 0:
            for day, count in daily_counts.items():
                daily_pattern[day] = count / total_count
                
        return daily_pattern
        
    async def _detect_auth_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect authentication anomalies such as:
        - Login from unusual location/IP
        - Login at unusual time
        - Multiple failed login attempts
        - Unusual account privilege usage
        - Rapid succession of logins from different locations
        - First-time administrative actions
        """
        user_id = event.get('data', {}).get('user_id')
        if not user_id:
            return None
            
        # Parse timestamp
        timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday() + 1  # MongoDB dayOfWeek: 1=Sunday, 7=Saturday
        
        # Check for unusual login time using seasonal patterns
        if 'authentication' in self.hourly_patterns:
            hourly_pattern = self.hourly_patterns['authentication']
            if hour_of_day in hourly_pattern:
                expected_probability = hourly_pattern[hour_of_day]
                # If probability of activity at this hour is very low compared to peak hours
                max_probability = max(hourly_pattern.values())
                if expected_probability < max_probability * 0.2:  # Less than 20% of peak activity time
                    return {
                        "name": "Unusual Authentication Time",
                        "description": f"Authentication at {hour_of_day}:00, outside normal activity patterns",
                        "severity": "medium",
                        "detection_type": "anomaly",
                        "subtype": "auth_time_anomaly",
                        "confidence": 0.7 + (max_probability - expected_probability),
                        "tags": ["authentication", "time-anomaly", "behavioral"]
                    }
        
        # Get user's historical login data
        auth_history = await self.db.events.find({
            'event_type': 'authentication',
            'data.user_id': user_id,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
        }).to_list(length=1000)
        
        # Skip if we don't have enough history
        if len(auth_history) < 5:
            return None
            
        # Extract features for behavioral analysis
        login_hours = []
        login_days = []
        login_ips = set()
        admin_actions = []
        
        for auth in auth_history:
            auth_time = datetime.fromisoformat(auth.get('timestamp'))
            login_hours.append(auth_time.hour)
            login_days.append(auth_time.weekday() + 1)
            
            ip = auth.get('data', {}).get('source_ip')
            if ip:
                login_ips.add(ip)
                
            action = auth.get('data', {}).get('action')
            is_admin = auth.get('data', {}).get('is_admin_action', False)
            if is_admin and action:
                admin_actions.append(action)
                
        # Check for login from unusual IP
        source_ip = event.get('data', {}).get('source_ip')
        if source_ip and source_ip not in login_ips and len(login_ips) >= 3:
            # Check if this IP is from a different geographical location (simple check)
            ip_class = self._get_ip_class(source_ip)
            different_location = True
            
            for known_ip in login_ips:
                if self._get_ip_class(known_ip) == ip_class:
                    different_location = False
                    break
                    
            if different_location:
                return {
                    "name": "Authentication from New Location",
                    "description": f"User {user_id} authenticated from a new IP ({source_ip}) not seen in their history",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "auth_location_anomaly",
                    "confidence": 0.85,
                    "tags": ["authentication", "location-anomaly", "behavioral"]
                }
                
        # Check for administrative action anomalies
        action = event.get('data', {}).get('action')
        is_admin = event.get('data', {}).get('is_admin_action', False)
        
        if is_admin and action and action not in admin_actions and len(admin_actions) > 0:
            return {
                "name": "Unusual Administrative Action",
                "description": f"User {user_id} performed new admin action '{action}' not in their normal behavior",
                "severity": "high",
                "detection_type": "anomaly",
                "subtype": "admin_action_anomaly",
                "confidence": 0.8,
                "tags": ["authentication", "admin", "privilege-escalation", "behavioral"]
            }
        
        # Check for failed login attempts
        if event.get('data', {}).get('status') == 'failed':
            # Count recent failed attempts
            recent_failures = await self.db.events.count_documents({
                'event_type': 'authentication',
                'data.user_id': user_id,
                'data.status': 'failed',
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(minutes=30)).isoformat()}
            })
            
            if recent_failures >= 5:
                return {
                    "name": "Multiple Failed Login Attempts",
                    "description": f"User {user_id} had {recent_failures} failed login attempts in the past 30 minutes",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "auth_brute_force",
                    "confidence": min(0.95, recent_failures / 10),
                    "tags": ["authentication", "brute-force", "credential-access"]
                }
                
        # Check for rapid succession of authentications from different locations
        if source_ip:
            recent_auths = await self.db.events.find({
                'event_type': 'authentication',
                'data.user_id': user_id,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(minutes=60)).isoformat()}
            }).sort('timestamp', -1).to_list(length=10)
            
            if len(recent_auths) >= 3:
                # Check if we have logins from different locations in short time
                recent_ips = set(auth.get('data', {}).get('source_ip', '') for auth in recent_auths)
                if len(recent_ips) >= 3:  # 3 or more different IPs
                    # Verify these are actually different networks
                    ip_classes = set(self._get_ip_class(ip) for ip in recent_ips if ip)
                    if len(ip_classes) >= 2:  # At least 2 different network classes
                        return {
                            "name": "Impossible Travel Detection",
                            "description": f"User {user_id} authenticated from multiple distant locations in short time period",
                            "severity": "critical",
                            "detection_type": "anomaly",
                            "subtype": "impossible_travel",
                            "confidence": 0.9,
                            "tags": ["authentication", "location-anomaly", "credential-theft", "behavioral"]
                        }
                
        return None
        
    async def _detect_network_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect network anomalies such as:
        - Unusual traffic volume
        - Communication with unusual destinations
        - Unusual protocol usage
        - Data exfiltration patterns
        - Beaconing behavior
        - DNS anomalies
        - Scanning activity
        """
        src_ip = event.get('data', {}).get('src_ip')
        dst_ip = event.get('data', {}).get('dst_ip')
        bytes_sent = event.get('data', {}).get('bytes_sent', 0)
        bytes_received = event.get('data', {}).get('bytes_received', 0)
        protocol = event.get('data', {}).get('protocol', '').lower()
        dst_port = event.get('data', {}).get('dst_port', 0)
        
        if not src_ip or not dst_ip:
            return None
            
        # Detect beaconing behavior (regular communication patterns)
        if await self._detect_beaconing(src_ip, dst_ip):
            return {
                "name": "Potential C2 Beaconing",
                "description": f"Regular communication pattern detected between {src_ip} and {dst_ip}",
                "severity": "high",
                "detection_type": "anomaly",
                "subtype": "network_beaconing",
                "confidence": 0.85,
                "tags": ["network", "command-and-control", "beaconing", "behavioral"]
            }
            
        # Check for unusual traffic volume
        if bytes_sent > 0:
            # Get historical traffic volumes for this source IP
            historical_traffic = await self.db.events.find({
                'event_type': 'network',
                'data.src_ip': src_ip,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
            }).to_list(length=500)
            
            if len(historical_traffic) >= 10:
                traffic_volumes = [e.get('data', {}).get('bytes_sent', 0) for e in historical_traffic]
                
                # Use robust statistics (median and MAD instead of mean/stdev)
                median_volume = statistics.median(traffic_volumes)
                mad = stats.median_abs_deviation(traffic_volumes, scale='normal')
                
                # Detect if current traffic is significantly higher than normal
                if mad > 0 and bytes_sent > median_volume + (self.anomaly_threshold * 2 * mad):
                    zscore = (bytes_sent - median_volume) / mad if mad > 0 else 10
                    return {
                        "name": "Unusual Network Traffic Volume",
                        "description": f"Traffic volume ({bytes_sent} bytes) is {zscore:.1f} deviations above normal",
                        "severity": "medium",
                        "detection_type": "anomaly",
                        "subtype": "network_volume_anomaly",
                        "confidence": min(0.95, zscore / 10),
                        "tags": ["network", "data-exfiltration", "behavioral"]
                    }
                    
        # Check for data exfiltration patterns
        if bytes_sent > 0 and bytes_received > 0:
            # Calculate ratio of data sent to received
            ratio = bytes_sent / bytes_received if bytes_received > 0 else float('inf')
            
            # Typically, clients receive more data than they send (ratio < 1)
            # High outbound/inbound ratio could indicate exfiltration
            if ratio > 10 and bytes_sent > 1000000:  # 1MB
                return {
                    "name": "Potential Data Exfiltration",
                    "description": f"Unusual outbound/inbound ratio: {ratio:.1f} with {bytes_sent} bytes sent",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "data_exfiltration",
                    "confidence": min(0.9, math.log10(ratio) / 3),
                    "tags": ["network", "data-exfiltration", "behavioral"]
                }
                
        # Check for port scanning behavior
        if await self._detect_port_scanning(src_ip):
            return {
                "name": "Port Scanning Activity",
                "description": f"{src_ip} is connecting to multiple ports in rapid succession",
                "severity": "medium",
                "detection_type": "anomaly",
                "subtype": "port_scanning",
                "confidence": 0.8,
                "tags": ["network", "scanning", "reconnaissance"]
            }
            
        # Check for unusual destination
        historical_destinations = await self.db.events.distinct('data.dst_ip', {
            'event_type': 'network',
            'data.src_ip': src_ip,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
        })
        
        if len(historical_destinations) >= 5 and dst_ip not in historical_destinations:
            # Check if this is likely a high-risk destination
            is_high_risk = await self._check_high_risk_destination(dst_ip)
            
            if is_high_risk:
                return {
                    "name": "Communication with High-Risk Destination",
                    "description": f"First time {src_ip} has connected to high-risk IP {dst_ip}",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "network_destination_anomaly",
                    "confidence": 0.85,
                    "tags": ["network", "unusual-connection", "command-and-control"]
                }
            else:
                return {
                    "name": "Communication with Unusual Destination",
                    "description": f"First time {src_ip} has connected to {dst_ip} in the baseline period",
                    "severity": "low",
                    "detection_type": "anomaly",
                    "subtype": "network_destination_anomaly",
                    "confidence": 0.65,
                    "tags": ["network", "unusual-connection"]
                }
                
        # Check for unusual protocol usage on non-standard ports
        if protocol in ['http', 'https'] and dst_port not in [80, 443, 8080, 8443]:
            return {
                "name": "Web Protocol on Non-Standard Port",
                "description": f"{protocol.upper()} traffic detected on unusual port {dst_port}",
                "severity": "medium",
                "detection_type": "anomaly",
                "subtype": "protocol_anomaly",
                "confidence": 0.75,
                "tags": ["network", "evasion", "command-and-control"]
            }
                
        return None
        
    async def _detect_beaconing(self, src_ip: str, dst_ip: str) -> bool:
        """
        Detect beaconing behavior (regular communication patterns) between two IPs.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            True if beaconing is detected, False otherwise
        """
        # Get recent communications between these IPs
        recent_comms = await self.db.events.find({
            'event_type': 'network',
            'data.src_ip': src_ip,
            'data.dst_ip': dst_ip,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(hours=24)).isoformat()}
        }).sort('timestamp', 1).to_list(length=100)
        
        if len(recent_comms) < 5:
            return False  # Not enough data
            
        # Extract timestamps and convert to seconds between communications
        timestamps = []
        try:
            for comm in recent_comms:
                timestamp = datetime.fromisoformat(comm.get('timestamp'))
                timestamps.append(timestamp)
        except (ValueError, TypeError):
            return False
            
        # Calculate intervals between communications
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
            
        # Check if intervals are regular (low variance)
        if len(intervals) < 4:
            return False
            
        mean_interval = statistics.mean(intervals)
        if mean_interval < 10:
            return False  # Too frequent, likely normal traffic
            
        # Calculate the coefficient of variation (CV)
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev / mean_interval if mean_interval > 0 else float('inf')
        
        # Low CV indicates regular intervals (potential beaconing)
        return cv < 0.3 and mean_interval > 30  # Regular interval > 30 seconds
    
    async def _detect_port_scanning(self, src_ip: str) -> bool:
        """
        Detect port scanning behavior from an IP.
        
        Args:
            src_ip: Source IP address to check
            
        Returns:
            True if port scanning is detected, False otherwise
        """
        # Get recent connections from this IP
        recent_connections = await self.db.events.find({
            'event_type': 'network',
            'data.src_ip': src_ip,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(minutes=5)).isoformat()}
        }).to_list(length=100)
        
        if len(recent_connections) < 10:
            return False  # Not enough connections
            
        # Extract unique destination ports
        dst_ports = set()
        for conn in recent_connections:
            port = conn.get('data', {}).get('dst_port')
            if port:
                dst_ports.add(port)
                
        # Check if we have many unique ports in a short time
        return len(dst_ports) > 15
        
    async def _check_high_risk_destination(self, ip_address: str) -> bool:
        """
        Check if an IP is a high-risk destination based on:
        - Known bad IPs from threat intelligence
        - Unusual IP ranges
        - Recent alerts involving this IP
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if high risk, False otherwise
        """
        # Check for recent alerts involving this IP
        recent_alerts = await self.db.alerts.count_documents({
            '$or': [
                {'details.event.data.src_ip': ip_address},
                {'details.event.data.dst_ip': ip_address}
            ],
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=7)).isoformat()}
        })
        
        if recent_alerts > 0:
            return True
            
        # TODO: In a production system, we would check threat intelligence feeds here
        
        # Basic check for suspicious IP ranges (e.g., known VPN/Tor exit nodes)
        suspicious_ranges = [
            '185.220.', '51.15.', '62.102.', '89.234.',  # Potential Tor exit nodes
            '104.149.', '185.100.', '193.218.'  # Example suspicious ranges
        ]
        
        for ip_range in suspicious_ranges:
            if ip_address.startswith(ip_range):
                return True
                
        return False
        
    def _get_ip_class(self, ip: str) -> str:
        """
        Get a simple classification of an IP address based on the first two octets.
        Used for basic geographical comparison.
        
        Args:
            ip: IP address to classify
            
        Returns:
            IP class string
        """
        if not ip:
            return ""
            
        parts = ip.split('.')
        if len(parts) != 4:
            return ip
            
        return f"{parts[0]}.{parts[1]}"
    
    async def _detect_file_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect file-related anomalies such as:
        - Mass file deletions or modifications
        - Access to sensitive files
        - Unusual file operations
        - Ransomware indicators
        - Unusual file access patterns
        """
        filepath = event.get('data', {}).get('filepath', '')
        operation = event.get('data', {}).get('operation', '')
        user_id = event.get('data', {}).get('user_id', '')
        process_name = event.get('data', {}).get('process_name', '')
        file_extension = event.get('data', {}).get('file_extension', '')
        
        if not filepath or not operation:
            return None
            
        # Check for sensitive file access
        sensitive_paths = ['/etc/passwd', '/etc/shadow', '/var/log', 
                          '/root/.ssh', '/.ssh', 'C:\\Windows\\System32',
                          'boot.ini', 'SAM', 'NTDS.dit', '/etc/sudoers',
                          'web.config', 'wp-config.php', '.env', 'id_rsa',
                          'credentials', 'password', '.aws/credentials']
                          
        is_sensitive = any(sens in filepath.lower() for sens in sensitive_paths)
        
        if is_sensitive:
            # Check if user has historically accessed this file
            historical_access = await self.db.events.count_documents({
                'event_type': 'file',
                'data.filepath': filepath,
                'data.user_id': user_id,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
            })
            
            if historical_access == 0:
                return {
                    "name": "Sensitive File Access",
                    "description": f"First time user {user_id} has accessed sensitive file/path {filepath}",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "file_access_anomaly",
                    "confidence": 0.8,
                    "tags": ["file-access", "sensitive-data", "credential-access"]
                }
                
        # Check for mass file operations (potential ransomware indicator)
        if operation in ['delete', 'modify', 'encrypt', 'rename', 'write']:
            # Count recent operations by this user/process
            recent_operations = await self.db.events.count_documents({
                'event_type': 'file',
                'data.operation': operation,
                'data.user_id': user_id,
                'data.process_name': process_name,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(minutes=5)).isoformat()}
            })
            
            if recent_operations >= 10:
                # If we're seeing a lot of rename/write operations to suspicious extensions
                # it's likely ransomware
                ransomware_extensions = ['.crypt', '.crypto', '.encrypted', '.enc', '.locked', 
                                        '.crypted', '.encrypt', '.kraken', '.zzz', '.wncry',
                                        '.cerber', '.locky', '.zepto', '.osiris', '.wallet']
                                        
                is_ransomware = False
                if operation in ['rename', 'write'] and file_extension:
                    is_ransomware = any(file_extension.lower().endswith(ext) for ext in ransomware_extensions)
                
                if is_ransomware:
                    return {
                        "name": "Potential Ransomware Activity",
                        "description": f"Process {process_name} performed {operation} on {recent_operations} files with ransomware extension",
                        "severity": "critical",
                        "detection_type": "anomaly",
                        "subtype": "ransomware_activity",
                        "confidence": 0.95,
                        "tags": ["file-operation", "ransomware", "encryption", "impact"]
                    }
                else:
                    return {
                        "name": "Mass File Operation",
                        "description": f"User {user_id} performed {operation} operation on {recent_operations} files in 5 minutes",
                        "severity": "high",
                        "detection_type": "anomaly",
                        "subtype": "mass_file_operation",
                        "confidence": min(0.95, recent_operations / 20),
                        "tags": ["file-operation", "potential-ransomware"]
                    }
                    
        # Check for unusual file access pattern (e.g., reading many files in sequence)
        if operation == 'read':
            # Get recent read operations by this process
            recent_reads = await self.db.events.find({
                'event_type': 'file',
                'data.operation': 'read',
                'data.process_name': process_name,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(minutes=15)).isoformat()}
            }).sort('timestamp', 1).to_list(length=100)
            
            if len(recent_reads) > 20:
                # Check if the files being read are of similar types (data mining)
                extensions = {}
                for read_event in recent_reads:
                    ext = read_event.get('data', {}).get('file_extension', '').lower()
                    if ext:
                        extensions[ext] = extensions.get(ext, 0) + 1
                        
                # If 70% of files have the same extension, it might indicate data mining
                if extensions:
                    max_ext = max(extensions, key=extensions.get)
                    max_count = extensions[max_ext]
                    
                    if max_count / len(recent_reads) > 0.7 and max_ext in ['.doc', '.xls', '.pdf', '.txt', '.csv', '.db', '.sql']:
                        return {
                            "name": "Potential Data Mining Activity",
                            "description": f"Process {process_name} read {max_count} {max_ext} files in 15 minutes",
                            "severity": "medium",
                            "detection_type": "anomaly",
                            "subtype": "data_mining",
                            "confidence": 0.75,
                            "tags": ["file-access", "data-collection", "exfiltration-preparation"]
                        }
                
        return None
        
    async def _detect_process_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect process-related anomalies such as:
        - Unusual process relationships (parent/child)
        - Processes running from unusual locations
        - Processes with unusual command lines
        - Process injection indicators
        - Unusual process timing
        """
        process_name = event.get('data', {}).get('process_name', '')
        process_path = event.get('data', {}).get('process_path', '')
        command_line = event.get('data', {}).get('command_line', '')
        parent_process = event.get('data', {}).get('parent_process_name', '')
        user_id = event.get('data', {}).get('user_id', '')
        
        if not process_name:
            return None
            
        # Check for processes running from unusual locations
        suspicious_locations = ['\\temp\\', '\\downloads\\', '\\appdata\\local\\temp\\', 
                              '/tmp/', '/dev/shm/', '\\recycle.bin\\']
                              
        if process_path and any(loc in process_path.lower() for loc in suspicious_locations):
            # Check if this is a system process that shouldn't run from these locations
            system_processes = ['svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe', 
                              'services.exe', 'smss.exe', 'explorer.exe', 'spoolsv.exe']
                              
            if any(proc.lower() == process_name.lower() for proc in system_processes):
                return {
                    "name": "System Process in Unusual Location",
                    "description": f"System process {process_name} running from suspicious location: {process_path}",
                    "severity": "critical",
                    "detection_type": "anomaly",
                    "subtype": "process_location_anomaly",
                    "confidence": 0.9,
                    "tags": ["process", "masquerading", "defense-evasion"]
                }
            else:
                return {
                    "name": "Process in Suspicious Location",
                    "description": f"Process {process_name} running from suspicious location: {process_path}",
                    "severity": "medium",
                    "detection_type": "anomaly",
                    "subtype": "process_location_anomaly",
                    "confidence": 0.7,
                    "tags": ["process", "defense-evasion"]
                }
                
        # Check for unusual parent-child process relationships
        unusual_relationships = [
            {'parent': 'explorer.exe', 'child': 'powershell.exe'},
            {'parent': 'excel.exe', 'child': 'cmd.exe'},
            {'parent': 'word.exe', 'child': 'powershell.exe'},
            {'parent': 'outlook.exe', 'child': 'cmd.exe'},
            {'parent': 'services.exe', 'child': 'cmd.exe'},
            {'parent': 'w3wp.exe', 'child': 'cmd.exe'},
            {'parent': 'explorer.exe', 'child': 'net.exe'},
            {'parent': 'wmiprvse.exe', 'child': 'powershell.exe'}
        ]
        
        if parent_process:
            for rel in unusual_relationships:
                if (parent_process.lower() == rel['parent'].lower() and 
                    process_name.lower() == rel['child'].lower()):
                    return {
                        "name": "Unusual Process Relationship",
                        "description": f"Suspicious parent-child process relationship: {parent_process} -> {process_name}",
                        "severity": "high",
                        "detection_type": "anomaly",
                        "subtype": "process_relationship_anomaly",
                        "confidence": 0.85,
                        "tags": ["process", "execution-chain", "suspicious-execution"]
                    }
                    
        # Check for suspicious command line parameters
        suspicious_commands = [
            '-hidden', '-enc', '-encodedcommand', '-nop', '-bypass', '-windowstyle hidden',
            'iex(', 'invoke-expression', 'invoke-mimikatz', 'invoke-webrequest',
            'net user /add', 'net localgroup administrators /add',
            'reg add', 'vssadmin delete', 'bcdedit', 'wmic shadow',
            'rundll32', 'regsvr32', '/transfer', 'certutil -decode'
        ]
        
        if command_line:
            cmd_lower = command_line.lower()
            for susp_cmd in suspicious_commands:
                if susp_cmd.lower() in cmd_lower:
                    return {
                        "name": "Suspicious Command Parameters",
                        "description": f"Process {process_name} used suspicious command parameters: {susp_cmd}",
                        "severity": "high",
                        "detection_type": "anomaly",
                        "subtype": "suspicious_command",
                        "confidence": 0.8,
                        "tags": ["process", "command-line", "execution"]
                    }
                    
        # Check for potential process injection
        if command_line and ('createremotethread' in cmd_lower or 
                          'virtualallocex' in cmd_lower or 
                          'ntmapviewofsection' in cmd_lower or
                          'reflective' in cmd_lower or
                          'shellcode' in cmd_lower):
            return {
                "name": "Potential Process Injection",
                "description": f"Process {process_name} exhibited potential process injection indicators",
                "severity": "critical",
                "detection_type": "anomaly",
                "subtype": "process_injection",
                "confidence": 0.85,
                "tags": ["process", "injection", "defense-evasion"]
            }
            
        # Check for unusual process timing (e.g., system processes starting at odd times)
        if process_name.lower() in ['svchost.exe', 'lsass.exe', 'services.exe']:
            # System processes typically start at boot time
            # If we see them starting much later, it might be suspicious
            timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
            system_uptime = await self._get_system_uptime(event.get('source', ''))
            
            if system_uptime and system_uptime > 3600:  # System has been up for more than an hour
                return {
                    "name": "Unusual System Process Timing",
                    "description": f"System process {process_name} started long after system boot",
                    "severity": "high",
                    "detection_type": "anomaly",
                    "subtype": "process_timing_anomaly",
                    "confidence": 0.8,
                    "tags": ["process", "persistence", "suspicious-execution"]
                }
                
        return None
        
    async def _get_system_uptime(self, source: str) -> Optional[float]:
        """
        Get the system uptime for a given source.
        
        Args:
            source: System source identifier
            
        Returns:
            Uptime in seconds or None if not available
        """
        # In a real system, this would query the actual system uptime
        # For demo purposes, we'll simulate with a database lookup
        system_info = await self.db.system_info.find_one({
            'source': source
        })
        
        if system_info and 'boot_time' in system_info:
            try:
                boot_time = datetime.fromisoformat(system_info['boot_time'])
                return (datetime.utcnow() - boot_time).total_seconds()
            except (ValueError, TypeError):
                return None
                
        return None
        
    async def _detect_frequency_anomalies(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect anomalies based on event frequency:
        - Unusual number of events from a source
        - Unusual distribution of event types
        - Time-based anomalies (activity during unusual hours)
        """
        event_type = event.get('event_type', '')
        source = event.get('source', '')
        timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
        
        # Get count of events of this type in the last hour
        recent_count = await self.db.events.count_documents({
            'event_type': event_type,
            'source': source,
            'timestamp': {'$gte': (datetime.utcnow() - timedelta(hours=1)).isoformat()}
        })
        
        # Check hourly patterns using the cached patterns if available
        hour_of_day = timestamp.hour
        if event_type in self.hourly_patterns:
            hourly_pattern = self.hourly_patterns[event_type]
            if hour_of_day in hourly_pattern:
                expected_probability = hourly_pattern[hour_of_day]
                # If we're seeing a lot of activity during normally quiet hours
                if expected_probability < 0.03 and recent_count > 20:  # Low expected activity but high current activity
                    return {
                        "name": "Unusual Activity Timing",
                        "description": f"High volume of {event_type} events from {source} during typically inactive hour {hour_of_day}",
                        "severity": "medium",
                        "detection_type": "anomaly",
                        "subtype": "temporal_anomaly",
                        "confidence": 0.75,
                        "tags": ["timing", "frequency-analysis", "behavioral"]
                    }
        
        # Get historical hourly counts for z-score calculation
        pipeline = [
            {'$match': {
                'event_type': event_type,
                'source': source,
                'timestamp': {'$gte': (datetime.utcnow() - timedelta(days=self.baseline_window)).isoformat()}
            }},
            {'$group': {
                '_id': {
                    'hour': {'$hour': {'$dateFromString': {'dateString': '$timestamp'}}},
                    'day': {'$dayOfMonth': {'$dateFromString': {'dateString': '$timestamp'}}}
                },
                'count': {'$sum': 1}
            }}
        ]
        
        hourly_counts = await self.db.events.aggregate(pipeline).to_list(length=1000)
        
        if len(hourly_counts) >= 24:  # If we have at least a day's worth of hourly data
            counts = [doc['count'] for doc in hourly_counts]
            
            # Use robust statistics
            median_count = statistics.median(counts)
            mad = stats.median_abs_deviation(counts, scale='normal')
            
            # Calculate modified z-score
            if mad > 0:
                zscore = (recent_count - median_count) / mad
                
                # If current count is significantly higher than normal
                if zscore > self.anomaly_threshold:
                    return {
                        "name": "Unusual Event Frequency",
                        "description": f"Frequency of {event_type} events from {source} ({recent_count} in last hour) is {zscore:.1f} standard deviations above normal",
                        "severity": "medium",
                        "detection_type": "anomaly",
                        "subtype": "frequency_anomaly",
                        "confidence": min(0.9, zscore / 7),
                        "tags": ["frequency-analysis"]
                    }
                
        return None