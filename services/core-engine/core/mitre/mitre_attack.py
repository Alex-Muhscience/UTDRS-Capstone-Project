"""
MITRE ATT&CK Framework integration for the UTDRS core engine.
Provides mapping between detections and MITRE tactics, techniques, and procedures.
"""
from typing import Dict, List, Any, Optional, Tuple
import json
import os
from utils.logger import get_logger

logger = get_logger(__name__)

class MitreAttackMapper:
    """
    Maps alerts and detections to the MITRE ATT&CK framework.
    """
    
    def __init__(self, mitre_data_file: Optional[str] = None):
        """
        Initialize the MITRE ATT&CK mapper.
        
        Args:
            mitre_data_file: Path to a MITRE ATT&CK data file (optional)
        """
        self.mitre_data = {}
        self.tactics = {}
        self.techniques = {}
        self.mitigations = {}
        
        # Load MITRE ATT&CK data
        if mitre_data_file and os.path.exists(mitre_data_file):
            self._load_from_file(mitre_data_file)
        else:
            self._load_default_data()
    
    def _load_from_file(self, mitre_data_file: str):
        """
        Load MITRE ATT&CK data from a file.
        
        Args:
            mitre_data_file: Path to the data file
        """
        try:
            with open(mitre_data_file, 'r') as f:
                self.mitre_data = json.load(f)
                
            # Process tactics
            for tactic in self.mitre_data.get('tactics', []):
                tactic_id = tactic.get('id')
                if tactic_id:
                    self.tactics[tactic_id] = tactic
                    
            # Process techniques
            for technique in self.mitre_data.get('techniques', []):
                technique_id = technique.get('id')
                if technique_id:
                    self.techniques[technique_id] = technique
                    
            # Process mitigations
            for mitigation in self.mitre_data.get('mitigations', []):
                mitigation_id = mitigation.get('id')
                if mitigation_id:
                    self.mitigations[mitigation_id] = mitigation
                    
            logger.info(f"Loaded MITRE ATT&CK data: {len(self.tactics)} tactics, " 
                        f"{len(self.techniques)} techniques, {len(self.mitigations)} mitigations")
                        
        except Exception as e:
            logger.error(f"Error loading MITRE ATT&CK data from {mitre_data_file}: {str(e)}")
            self._load_default_data()
    
    def _load_default_data(self):
        """
        Load default MITRE ATT&CK data (minimal subset).
        """
        # Tactics (TA*)
        self.tactics = {
            "TA0001": {"id": "TA0001", "name": "Initial Access", "description": "Techniques that use various entry vectors to gain initial access to the network."},
            "TA0002": {"id": "TA0002", "name": "Execution", "description": "Techniques that result in execution of adversary-controlled code on a local or remote system."},
            "TA0003": {"id": "TA0003", "name": "Persistence", "description": "Techniques that maintain access to systems across restarts, credential changes, and other interruptions."},
            "TA0004": {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques that enable adversaries to gain higher-level permissions."},
            "TA0005": {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques used to avoid detection and hide activity."},
            "TA0006": {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials like account names and passwords."},
            "TA0007": {"id": "TA0007", "name": "Discovery", "description": "Techniques used to gain knowledge about the system and internal network."},
            "TA0008": {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques that enable adversaries to move through the environment."},
            "TA0009": {"id": "TA0009", "name": "Collection", "description": "Techniques used to gather information relevant to the adversary's objective."},
            "TA0010": {"id": "TA0010", "name": "Exfiltration", "description": "Techniques used to steal data from the network."},
            "TA0011": {"id": "TA0011", "name": "Command and Control", "description": "Techniques that allow adversaries to communicate with systems under their control."},
            "TA0040": {"id": "TA0040", "name": "Impact", "description": "Techniques that manipulate, interrupt, or destroy systems and data."}
        }
        
        # Common techniques (T*)
        self.techniques = {
            "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."},
            "T1059.001": {"id": "T1059.001", "name": "PowerShell", "description": "Adversaries may abuse PowerShell commands and scripts for execution."},
            "T1078": {"id": "T1078", "name": "Valid Accounts", "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access or maintaining access."},
            "T1078.002": {"id": "T1078.002", "name": "Domain Accounts", "description": "Adversaries may obtain and abuse credentials of a domain account."},
            "T1110": {"id": "T1110", "name": "Brute Force", "description": "Adversaries may use brute force techniques to gain access to accounts."},
            "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "description": "Adversaries may encrypt data on target systems or on large numbers of systems to interrupt availability."},
            "T1566": {"id": "T1566", "name": "Phishing", "description": "Adversaries may send phishing messages to gain access to victim systems."},
            "T1204": {"id": "T1204", "name": "User Execution", "description": "Adversaries may rely on users interacting with a malicious file or link."},
            "T1046": {"id": "T1046", "name": "Network Service Scanning", "description": "Adversaries may scan for services to identify entry points to use for lateral movement."},
            "T1048": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel."},
            "T1071": {"id": "T1071", "name": "Application Layer Protocol", "description": "Adversaries may communicate using application layer protocols to avoid detection."},
            "T1071.004": {"id": "T1071.004", "name": "DNS", "description": "Adversaries may communicate using the DNS protocol to avoid detection."},
            "T1056": {"id": "T1056", "name": "Input Capture", "description": "Adversaries may use methods of capturing user input to obtain credentials or other sensitive information."},
            "T1552": {"id": "T1552", "name": "Unsecured Credentials", "description": "Adversaries may search for unsecured credentials in files, registries, or memory."},
            "T1562": {"id": "T1562", "name": "Impair Defenses", "description": "Adversaries may maliciously modify security tools to hide their presence and defeat security controls."},
            "T1136": {"id": "T1136", "name": "Create Account", "description": "Adversaries may create an account to maintain access to victim systems."}
        }
        
        # Store complete data
        self.mitre_data = {
            "tactics": list(self.tactics.values()),
            "techniques": list(self.techniques.values()),
            "mitigations": []
        }
        
        logger.info("Loaded default MITRE ATT&CK data")
    
    def enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an alert with MITRE ATT&CK information.
        
        Args:
            alert: The alert to enrich
            
        Returns:
            The enriched alert
        """
        # Extract MITRE references from the alert
        tactics = []
        techniques = []
        
        # Extract from details
        details = alert.get('details', {})
        tactic_ids = details.get('mitre_tactics', [])
        technique_ids = details.get('mitre_techniques', [])
        
        # Look up tactic information
        for tactic_id in tactic_ids:
            if tactic_id in self.tactics:
                tactics.append({
                    "id": tactic_id,
                    "name": self.tactics[tactic_id].get('name', 'Unknown'),
                    "description": self.tactics[tactic_id].get('description', '')
                })
            else:
                tactics.append({"id": tactic_id, "name": "Unknown Tactic", "description": ""})
                
        # Look up technique information
        for technique_id in technique_ids:
            if technique_id in self.techniques:
                techniques.append({
                    "id": technique_id,
                    "name": self.techniques[technique_id].get('name', 'Unknown'),
                    "description": self.techniques[technique_id].get('description', '')
                })
            else:
                techniques.append({"id": technique_id, "name": "Unknown Technique", "description": ""})
                
        # Add enriched information to the alert
        enriched_alert = alert.copy()
        enriched_alert['mitre'] = {
            "tactics": tactics,
            "techniques": techniques
        }
        
        return enriched_alert
    
    def get_mitigations(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Get mitigations for the specified techniques.
        
        Args:
            technique_ids: List of technique IDs to get mitigations for
            
        Returns:
            List of mitigation dictionaries
        """
        # In a real implementation, we would look up mitigations from the MITRE data
        # For demonstration, we'll return some sample mitigations
        sample_mitigations = {
            "T1059": [
                {"id": "M1042", "name": "Disable or Remove Feature or Program", "description": "Remove or disable unused features or programs, especially PowerShell if not needed."},
                {"id": "M1026", "name": "Privileged Account Management", "description": "Manage privileges associated with command-line interpreters."}
            ],
            "T1059.001": [
                {"id": "M1040", "name": "Execution Prevention", "description": "Use PowerShell constrained language mode and Script Block Logging."},
                {"id": "M1026", "name": "Privileged Account Management", "description": "Restrict PowerShell execution to admins only where possible."}
            ],
            "T1078": [
                {"id": "M1032", "name": "Multi-factor Authentication", "description": "Use multi-factor authentication for user and privileged accounts."},
                {"id": "M1030", "name": "Network Segmentation", "description": "Apply network segmentation to restrict access to critical systems."}
            ],
            "T1110": [
                {"id": "M1032", "name": "Multi-factor Authentication", "description": "Use multi-factor authentication to mitigate risks from brute force attacks."},
                {"id": "M1036", "name": "Account Use Policies", "description": "Implement account lockout policies after failed login attempts."}
            ],
            "T1486": [
                {"id": "M1053", "name": "Data Backup", "description": "Perform regular backups and test restoration procedures."},
                {"id": "M1037", "name": "Filter Network Traffic", "description": "Filter network traffic to block known ransomware communication."}
            ],
            "T1566": [
                {"id": "M1054", "name": "Software Configuration", "description": "Configure email security solutions to block suspicious attachments and links."},
                {"id": "M1017", "name": "User Training", "description": "Train users to identify and report suspicious messages."}
            ],
            "T1204": [
                {"id": "M1017", "name": "User Training", "description": "Train users to identify and avoid suspicious files and links."},
                {"id": "M1049", "name": "Antivirus/Antimalware", "description": "Use antivirus solutions with behavioral detection capabilities."}
            ],
            "T1046": [
                {"id": "M1030", "name": "Network Segmentation", "description": "Use network segmentation to limit scanning effectiveness."},
                {"id": "M1035", "name": "Limit Access to Resource Over Network", "description": "Use firewalls to block access to services that should not be accessible."}
            ],
            "T1048": [
                {"id": "M1031", "name": "Network Intrusion Prevention", "description": "Use network intrusion detection systems to identify abnormal data transfers."},
                {"id": "M1037", "name": "Filter Network Traffic", "description": "Filter outbound network traffic to only allow approved protocols and destinations."}
            ]
        }
        
        # Return mitigations for the requested techniques
        mitigations = []
        for technique_id in technique_ids:
            if technique_id in sample_mitigations:
                mitigations.extend(sample_mitigations[technique_id])
                
        return mitigations
    
    def get_tactic_by_id(self, tactic_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a tactic by its ID.
        
        Args:
            tactic_id: The ID of the tactic to retrieve
            
        Returns:
            The tactic dictionary or None if not found
        """
        return self.tactics.get(tactic_id)
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a technique by its ID.
        
        Args:
            technique_id: The ID of the technique to retrieve
            
        Returns:
            The technique dictionary or None if not found
        """
        return self.techniques.get(technique_id)
    
    def get_tactics(self) -> List[Dict[str, Any]]:
        """
        Get all available tactics.
        
        Returns:
            List of tactic dictionaries
        """
        return list(self.tactics.values())
    
    def get_techniques(self, tactic_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all available techniques, optionally filtered by tactic.
        
        Args:
            tactic_id: Optional tactic ID to filter by
            
        Returns:
            List of technique dictionaries
        """
        if not tactic_id:
            return list(self.techniques.values())
            
        # In a real implementation, we would have mappings between tactics and techniques
        # For demonstration, we'll hardcode some relationships
        tactic_technique_map = {
            "TA0001": ["T1078", "T1566", "T1190"],  # Initial Access
            "TA0002": ["T1059", "T1059.001", "T1204"],  # Execution
            "TA0003": ["T1136"],  # Persistence
            "TA0004": ["T1078", "T1078.002"],  # Privilege Escalation
            "TA0005": ["T1562"],  # Defense Evasion
            "TA0006": ["T1110", "T1552"],  # Credential Access
            "TA0007": ["T1046"],  # Discovery
            "TA0009": ["T1056"],  # Collection
            "TA0010": ["T1048"],  # Exfiltration
            "TA0011": ["T1071", "T1071.004"],  # Command and Control
            "TA0040": ["T1486"]  # Impact
        }
        
        if tactic_id not in tactic_technique_map:
            return []
            
        technique_ids = tactic_technique_map[tactic_id]
        return [self.techniques[t_id] for t_id in technique_ids if t_id in self.techniques]
    
    def map_event_to_mitre(self, event: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """
        Map an event to MITRE tactics and techniques based on patterns.
        
        Args:
            event: The event to map
            
        Returns:
            Tuple of (tactic_ids, technique_ids)
        """
        event_type = event.get('event_type', '')
        tactic_ids = []
        technique_ids = []
        
        # Simple rule-based mapping
        if event_type == 'authentication':
            action = event.get('data', {}).get('action', '')
            status = event.get('data', {}).get('status', '')
            
            if status == 'failed' and event.get('data', {}).get('failure_count', 1) > 3:
                # Multiple failed logins could be brute force
                tactic_ids.append("TA0006")  # Credential Access
                technique_ids.append("T1110")  # Brute Force
            elif 'privilege' in action or 'admin' in action:
                # Privilege escalation activity
                tactic_ids.append("TA0004")  # Privilege Escalation
                technique_ids.append("T1078")  # Valid Accounts
                
        elif event_type == 'network':
            protocol = event.get('data', {}).get('protocol', '').lower()
            destination = event.get('data', {}).get('dst_ip', '')
            
            if protocol == 'dns':
                # DNS traffic could be C2
                tactic_ids.append("TA0011")  # Command and Control
                technique_ids.append("T1071.004")  # DNS
            elif event.get('data', {}).get('bytes_sent', 0) > 10000000:  # 10MB
                # Large data transfer could be exfiltration
                tactic_ids.append("TA0010")  # Exfiltration
                technique_ids.append("T1048")  # Exfiltration Over Alternative Protocol
                
        elif event_type == 'process':
            process_name = event.get('data', {}).get('process_name', '').lower()
            command_line = event.get('data', {}).get('command_line', '').lower()
            
            if 'powershell' in process_name:
                tactic_ids.append("TA0002")  # Execution
                technique_ids.append("T1059.001")  # PowerShell
            elif 'cmd' in process_name or 'bash' in process_name:
                tactic_ids.append("TA0002")  # Execution
                technique_ids.append("T1059")  # Command and Scripting Interpreter
                
        elif event_type == 'file':
            operation = event.get('data', {}).get('operation', '')
            filepath = event.get('data', {}).get('filepath', '').lower()
            
            if operation == 'encrypt' or '.encrypt' in filepath or '.locked' in filepath:
                tactic_ids.append("TA0040")  # Impact
                technique_ids.append("T1486")  # Data Encrypted for Impact
            elif 'passwd' in filepath or 'shadow' in filepath or '.ssh' in filepath:
                tactic_ids.append("TA0006")  # Credential Access
                technique_ids.append("T1552")  # Unsecured Credentials
                
        return tactic_ids, technique_ids