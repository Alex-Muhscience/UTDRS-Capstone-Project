from typing import Dict, Any, Optional, List
import os
import json
import numpy as np
from datetime import datetime
import pickle
from utils.logger import get_logger
from config import settings
from core.models.ml.model_registry import ModelRegistry

logger = get_logger(__name__)

class MLDetector:
    """
    Machine Learning-based threat detector that uses trained models to identify threats.
    """
    
    def __init__(self):
        self.model_registry = ModelRegistry(settings.MODEL_PATH)
        # Default confidence threshold for ML detections
        self.confidence_threshold = 0.7
        
    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect threats using machine learning models based on event type.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result dict if a threat is detected, None otherwise
        """
        # Determine which ML model to use based on event type
        event_type = event.get('event_type', '')
        
        if not event_type:
            logger.debug("Event missing type, skipping ML detection")
            return None
        
        # Route to appropriate specialized detector based on event type
        if any(t in event_type for t in ['email', 'url', 'web']):
            return await self._run_phishing_detection(event)
        elif any(t in event_type for t in ['file', 'process']):
            return await self._run_malware_detection(event)
        elif any(t in event_type for t in ['network', 'traffic', 'dns']):
            return await self._run_network_anomaly_detection(event)
        elif any(t in event_type for t in ['auth', 'login', 'user']):
            return await self._run_user_behavior_detection(event)
            
        # No matching specialized detector
        logger.debug(f"No specialized ML detector for event type: {event_type}")
        return None
        
    async def _run_phishing_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run phishing detection on email or URL events.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if phishing is detected, None otherwise
        """
        # In a production system, we would:
        # 1. Extract relevant features from the event (URL, email text, etc.)
        # 2. Preprocess those features (tokenization, normalization, etc.)
        # 3. Run the preprocessed features through the loaded model
        # 4. Return results based on model confidence
        
        # For demonstration, we'll use a simple feature extraction and simulate model prediction
        model_file = os.path.join(settings.MODEL_PATH, 'phishing', 'model.pkl')
        
        # Check if we have a model file
        if not os.path.exists(model_file):
            logger.warning(f"Phishing model not found at {model_file}")
            # Simulate a model prediction for demonstration
            return await self._simulate_phishing_detection(event)
            
        try:
            # Extract features based on event type
            if 'email' in event.get('event_type', ''):
                features = self._extract_email_features(event)
            else:  # URL event
                features = self._extract_url_features(event)
                
            # Load model
            with open(model_file, 'rb') as f:
                model = pickle.load(f)
                
            # Make prediction
            confidence = model.predict_proba([features])[0][1]  # Probability of phishing class
            
            # If confidence meets threshold, return detection
            if confidence > self.confidence_threshold:
                severity = "high" if confidence > 0.9 else "medium"
                
                return {
                    "name": "Potential Phishing Attempt",
                    "description": f"ML model detected phishing indicators with {confidence*100:.1f}% confidence",
                    "severity": severity,
                    "detection_type": "ml",
                    "model": "phishing_detector",
                    "confidence": confidence,
                    "tags": ["phishing", "ml-detection"],
                    "mitre_techniques": ["T1566"],  # Phishing
                    "mitre_tactics": ["TA0001"]     # Initial Access
                }
                
        except Exception as e:
            logger.error(f"Error in phishing detection: {str(e)}")
            
        return None
    
    def _extract_email_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract features from an email event for phishing detection.
        
        Args:
            event: The email event
            
        Returns:
            List of numerical features
        """
        # In a real implementation, this would extract and process various email features
        # For demonstration, we'll return a simple placeholder feature vector
        return [0.5, 0.3, 0.7, 0.2, 0.1]
    
    def _extract_url_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract features from a URL event for phishing detection.
        
        Args:
            event: The URL event
            
        Returns:
            List of numerical features
        """
        # In a real implementation, this would extract and process various URL features
        # For demonstration, we'll return a simple placeholder feature vector
        return [0.6, 0.4, 0.3, 0.8, 0.2]
        
    async def _simulate_phishing_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Simulate a phishing detection model for development/testing purposes.
        
        Args:
            event: The event to analyze
            
        Returns:
            Simulated detection result if phishing indicators are found, None otherwise
        """
        # Extract content based on event type
        content = ""
        score = 0.0
        
        if 'email' in event.get('event_type', ''):
            # Extract email content
            email_data = event.get('data', {})
            subject = email_data.get('subject', '').lower()
            body = email_data.get('body', '').lower()
            sender = email_data.get('sender', '').lower()
            
            content = f"{subject} {body}"
            
            # Simple rule-based scoring for demonstration
            phishing_keywords = [
                'urgent', 'account', 'verify', 'password', 'login', 'security', 
                'update', 'banking', 'click', 'link', 'confirm', 'suspend', 
                'unusual activity', 'credential', 'expire'
            ]
            
            score += sum(0.1 for kw in phishing_keywords if kw in content) 
            
            # Check for suspicious sender
            if '@' in sender and not any(legit in sender for legit in ['.com', '.org', '.edu', '.gov']):
                score += 0.2
                
            # Check for mismatch between display name and actual email
            if 'display_name' in email_data and 'sender' in email_data:
                display_name = email_data.get('display_name', '').lower()
                if any(company in display_name for company in ['paypal', 'amazon', 'bank', 'netflix']) and \
                   not any(company in sender for company in ['paypal', 'amazon', 'bank', 'netflix']):
                    score += 0.3
            
        else:  # URL event
            # Extract URL content
            url_data = event.get('data', {})
            url = url_data.get('url', '').lower()
            
            content = url
            
            # Simple rule-based scoring for demonstration
            if 'http:' in url and not 'https:' in url:
                score += 0.1
                
            suspicious_domains = [
                'login', 'account', 'secure', 'verify', 'update', 'billing',
                'payment', 'confirm', 'auth'
            ]
            
            # Check for suspicious domain
            if any(susp in url for susp in suspicious_domains):
                score += 0.1
                
            # Check for IP address in URL
            import re
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 0.2
                
            # Check for unusual TLD
            common_tlds = ['.com', '.org', '.net', '.gov', '.edu', '.co', '.io']
            if not any(tld in url for tld in common_tlds):
                score += 0.1
                
            # Check for excessive subdomains
            if url.count('.') > 3:
                score += 0.1
                
            # Check for encoded characters
            if '%' in url:
                score += 0.1
                
        # If score meets threshold, return detection
        if score > self.confidence_threshold:
            severity = "high" if score > 0.9 else "medium"
            
            return {
                "name": "Potential Phishing Attempt",
                "description": f"ML model detected phishing indicators with {score*100:.1f}% confidence",
                "severity": severity,
                "detection_type": "ml",
                "model": "phishing_detector_simulated",
                "confidence": score,
                "tags": ["phishing", "ml-detection"],
                "mitre_techniques": ["T1566"],  # Phishing
                "mitre_tactics": ["TA0001"]     # Initial Access
            }
            
        return None
        
    async def _run_malware_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run malware detection on file or process events.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if malware is detected, None otherwise
        """
        event_data = event.get('data', {})
        
        # In a real implementation, we would extract features such as:
        # - File hash or content
        # - Process behavior (file/registry/network operations)
        # - Memory patterns
        # - API call sequences
        
        # For demonstration, we'll use a simple rule-based simulation
        score = 0.0
        
        # Process behaviors that may indicate malware
        if 'process' in event.get('event_type', ''):
            # Process runs from temp directory
            if any(tmp_dir in event_data.get('process_path', '') 
                  for tmp_dir in ['temp', 'tmp', r'\Windows\Temp']):
                score += 0.2
                
            # Process with unusual name or path
            if event_data.get('process_name', '') in [
                'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe'
            ] and not event_data.get('process_path', '').lower().startswith(r'c:\windows\system32'):
                score += 0.3
                
            # Process making suspicious network connections
            connections = event_data.get('network_connections', [])
            if any(conn.get('remote_port') in [4444, 8080, 443, 8443] for conn in connections):
                score += 0.2
                
            # Process with suspicious command line
            cmdline = event_data.get('command_line', '').lower()
            if any(susp in cmdline for susp in [
                'powershell -enc', 'rundll32', 'regsvr32', 'bitsadmin', 'wscript', 
                'mshta', 'certutil -decode', 'iex(', 'invoke-expression', 'bypass'
            ]):
                score += 0.3
                
            # Process accessing system directories
            accessed_files = event_data.get('accessed_files', [])
            if any('/system32/' in file.lower() or '\\system32\\' in file.lower() for file in accessed_files):
                score += 0.1
                
        # File events that may indicate malware
        elif 'file' in event.get('event_type', ''):
            # Suspicious file extensions
            filepath = event_data.get('filepath', '').lower()
            suspicious_extensions = ['.exe', '.dll', '.ps1', '.vbs', '.js', '.hta', '.bat', '.cmd']
            if any(filepath.endswith(ext) for ext in suspicious_extensions):
                score += 0.1
                
            # Files in suspicious locations
            suspicious_locations = ['\\temp\\', '\\downloads\\', '\\appdata\\', '\\recycle']
            if any(loc in filepath for loc in suspicious_locations):
                score += 0.1
                
            # File operations indicative of ransomware
            operation = event_data.get('operation', '')
            if operation == 'rename' and any(ext in filepath for ext in ['.encrypted', '.locked', '.crypt', '.crypted']):
                score += 0.4
                
            # Check for file hash against known malware hashes
            file_hash = event_data.get('file_hash', '')
            # In a real system, we would check against a database of known malware hashes
            known_malware_hashes = []  # Placeholder
            if file_hash in known_malware_hashes:
                score += 0.5
                
        # If score meets threshold, return detection
        if score > self.confidence_threshold:
            severity = "critical" if score > 0.9 else "high" if score > 0.7 else "medium"
            
            # Determine if this is likely ransomware
            is_ransomware = False
            if 'file' in event.get('event_type', '') and event_data.get('operation', '') == 'rename' and \
               any(ext in event_data.get('filepath', '').lower() for ext in ['.encrypted', '.locked', '.crypt']):
                is_ransomware = True
                
            if is_ransomware:
                return {
                    "name": "Potential Ransomware Activity",
                    "description": f"ML model detected ransomware indicators with {score*100:.1f}% confidence",
                    "severity": "critical",
                    "detection_type": "ml",
                    "model": "ransomware_detector_simulated",
                    "confidence": score,
                    "tags": ["ransomware", "file-encryption", "ml-detection"],
                    "mitre_techniques": ["T1486"],  # Data Encrypted for Impact
                    "mitre_tactics": ["TA0040"]     # Impact
                }
            else:
                return {
                    "name": "Potential Malware Activity",
                    "description": f"ML model detected malware indicators with {score*100:.1f}% confidence",
                    "severity": severity,
                    "detection_type": "ml",
                    "model": "malware_detector_simulated",
                    "confidence": score,
                    "tags": ["malware", "ml-detection"],
                    "mitre_techniques": ["T1059"],  # Command and Scripting Interpreter
                    "mitre_tactics": ["TA0002"]     # Execution
                }
                
        return None
        
    async def _run_network_anomaly_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run network anomaly detection on network events.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if network anomaly is detected, None otherwise
        """
        event_data = event.get('data', {})
        
        # In a real implementation, we would:
        # 1. Extract network traffic patterns and features
        # 2. Apply trained anomaly detection models
        # 3. Compare with baseline network behavior
        
        # For demonstration, we'll use a simple rule-based simulation
        score = 0.0
        
        # Check traffic volume
        bytes_sent = event_data.get('bytes_sent', 0)
        bytes_received = event_data.get('bytes_received', 0)
        
        # Large data transfers could indicate data exfiltration
        if bytes_sent > 10000000:  # 10 MB
            score += 0.3
            
        # Unusual ports or protocols
        dst_port = event_data.get('dst_port', 0)
        protocol = event_data.get('protocol', '').lower()
        
        unusual_ports = [4444, 8888, 31337, 1337, 6666, 12345, 54321]
        if dst_port in unusual_ports:
            score += 0.2
            
        # Check for unusual protocol usage
        if protocol == 'icmp' and bytes_sent > 1000:  # ICMP tunneling
            score += 0.3
            
        # Check for scanning behavior (multiple connections in short time)
        connection_count = event_data.get('connection_count', 1)
        if connection_count > 10:
            score += 0.2
            
        # Check for connections to known malicious IPs
        dst_ip = event_data.get('dst_ip', '')
        # In a real system, we would check against threat intelligence data
        malicious_ips = []  # Placeholder
        if dst_ip in malicious_ips:
            score += 0.5
            
        # Check for DNS exfiltration indicators
        if protocol == 'dns':
            dns_query = event_data.get('dns_query', '')
            if len(dns_query) > 50:  # Long DNS query could be data exfiltration
                score += 0.2
                
        # If score meets threshold, return detection
        if score > self.confidence_threshold:
            severity = "high" if score > 0.9 else "medium"
            
            # Determine likely attack type
            if bytes_sent > 10000000:
                attack_type = "Data Exfiltration"
                techniques = ["T1048"]  # Exfiltration Over Alternative Protocol
                tactics = ["TA0010"]    # Exfiltration
            elif connection_count > 10:
                attack_type = "Network Scanning"
                techniques = ["T1046"]  # Network Service Scanning
                tactics = ["TA0007"]    # Discovery
            elif protocol == 'dns' and len(event_data.get('dns_query', '')) > 50:
                attack_type = "DNS Tunneling"
                techniques = ["T1071.004"]  # Application Layer Protocol: DNS
                tactics = ["TA0011"]        # Command and Control
            else:
                attack_type = "Suspicious Network Activity"
                techniques = ["T1071"]      # Application Layer Protocol
                tactics = ["TA0011"]        # Command and Control
            
            return {
                "name": f"Potential {attack_type}",
                "description": f"ML model detected network anomaly with {score*100:.1f}% confidence",
                "severity": severity,
                "detection_type": "ml",
                "model": "network_anomaly_detector_simulated",
                "confidence": score,
                "tags": ["network", "anomaly", "ml-detection"],
                "mitre_techniques": techniques,
                "mitre_tactics": tactics
            }
                
        return None
        
    async def _run_user_behavior_detection(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run user behavior anomaly detection on authentication or user events.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result if user behavior anomaly is detected, None otherwise
        """
        event_data = event.get('data', {})
        
        # In a real implementation, we would:
        # 1. Build user behavior profiles based on historical activity
        # 2. Apply anomaly detection to current behavior
        # 3. Calculate anomaly scores for different dimensions of behavior
        
        # For demonstration, we'll use a simple rule-based simulation
        score = 0.0
        
        # Extract user information
        user_id = event_data.get('user_id', '')
        timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
        action = event_data.get('action', '')
        source_ip = event_data.get('source_ip', '')
        
        # Check for activity at unusual hours
        hour = timestamp.hour
        if hour < 6 or hour > 22:  # Activity outside normal business hours
            score += 0.2
            
        # Check for access from unusual location
        # In a real system, we would have a list of usual locations for each user
        usual_ips = []  # Placeholder
        if source_ip and source_ip not in usual_ips:
            score += 0.2
            
        # Check for unusual account activities
        sensitive_actions = ['password_change', 'permission_change', 'user_create', 'group_add']
        if action in sensitive_actions:
            score += 0.2
            
        # Check for unusual resource access
        resource = event_data.get('resource', '')
        sensitive_resources = ['admin_panel', 'user_database', 'financial_reports', 'source_code']
        if any(res in resource for res in sensitive_resources):
            score += 0.2
            
        # Check for rapid succession of actions
        # In a real system, we would track action frequency and timing patterns
        action_count = event_data.get('action_count', 1)
        time_window = event_data.get('time_window', 60)  # seconds
        if action_count > 5 and time_window < 60:
            score += 0.3
            
        # If score meets threshold, return detection
        if score > self.confidence_threshold:
            severity = "high" if score > 0.9 else "medium"
            
            return {
                "name": "Unusual User Behavior",
                "description": f"ML model detected user behavior anomaly for user {user_id} with {score*100:.1f}% confidence",
                "severity": severity,
                "detection_type": "ml",
                "model": "user_behavior_detector_simulated",
                "confidence": score,
                "tags": ["user", "anomaly", "insider-threat", "ml-detection"],
                "mitre_techniques": ["T1078"],  # Valid Accounts
                "mitre_tactics": ["TA0004"]     # Privilege Escalation
            }
                
        return None