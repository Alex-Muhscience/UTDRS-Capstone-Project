import os
import re
import json
import hashlib
from typing import Dict, Any, Optional, List, Union
import yara
from utils.logger import get_logger
from config import settings

logger = get_logger(__name__)

class YaraRuleManager:
    """
    Manages YARA rules for file-based threat detection.
    Allows loading rules from files, compiling them, and matching them against files.
    """
    
    def __init__(self, rules_directory: str = None):
        """
        Initialize the YARA rule manager.
        
        Args:
            rules_directory: Directory containing YARA rule files (defaults to 'rules/yara' under project root)
        """
        self.rules_directory = rules_directory or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules', 'yara')
        self.rules = {}  # Dictionary to store compiled rules
        self.rule_metadata = {}  # Dictionary to store rule metadata
        self.ensure_directory_exists()
        self.load_rules()
        
    def ensure_directory_exists(self):
        """
        Ensure that the rules directory exists.
        """
        if not os.path.exists(self.rules_directory):
            os.makedirs(self.rules_directory)
            logger.info(f"Created YARA rules directory: {self.rules_directory}")
            # Create example rules directory
            examples_dir = os.path.join(self.rules_directory, 'examples')
            if not os.path.exists(examples_dir):
                os.makedirs(examples_dir)
                self._create_example_rules(examples_dir)
    
    def _create_example_rules(self, directory: str):
        """
        Create example YARA rules.
        
        Args:
            directory: Directory to create rules in
        """
        # Example rule for detecting potential ransomware
        ransomware_rule = '''
rule potential_ransomware {
    meta:
        description = "Detects potential ransomware characteristics"
        author = "UTDRS"
        severity = "critical"
        mitre_tactic = "Impact"
        mitre_technique = "T1486"
        tags = "ransomware,encryption,impact"
        
    strings:
        $encryption1 = "AES" nocase
        $encryption2 = "RSA" nocase
        $encryption3 = "encrypt" nocase
        $ransom1 = "bitcoin" nocase
        $ransom2 = "payment" nocase
        $ransom3 = "ransom" nocase
        $ransom4 = "your files" nocase
        $ransom5 = "recover" nocase
        $file_op1 = "*.pdf"
        $file_op2 = "*.doc"
        $file_op3 = "*.xls"
        $file_op4 = "*.jpg"
        $file_op5 = "decrypt"
        
    condition:
        (2 of ($encryption*)) and 
        (2 of ($ransom*)) and
        (1 of ($file_op*))
}
'''
        # Example rule for detecting potential backdoors
        backdoor_rule = '''
rule potential_backdoor {
    meta:
        description = "Detects potential backdoor characteristics"
        author = "UTDRS"
        severity = "high"
        mitre_tactic = "Persistence"
        mitre_technique = "T1543"
        tags = "backdoor,persistence,command-and-control"
        
    strings:
        $network1 = "socket" nocase
        $network2 = "connect" nocase
        $network3 = "recv" nocase
        $network4 = "send" nocase
        $persistence1 = "startup" nocase
        $persistence2 = "registry" nocase
        $persistence3 = "service" nocase
        $command1 = "cmd.exe" nocase
        $command2 = "powershell" nocase
        $command3 = "execute" nocase
        $command4 = "system(" nocase
        $stealth1 = "hidden" nocase
        $stealth2 = "hide" nocase
        
    condition:
        (2 of ($network*)) and 
        (1 of ($persistence*)) and
        (1 of ($command*)) and
        (1 of ($stealth*))
}
'''
        # Example rule for detecting potential data theft/exfiltration
        data_theft_rule = '''
rule potential_data_theft {
    meta:
        description = "Detects potential data theft/exfiltration characteristics"
        author = "UTDRS"
        severity = "high"
        mitre_tactic = "Exfiltration"
        mitre_technique = "T1048"
        tags = "exfiltration,data-theft,collection"
        
    strings:
        $file_access1 = "open(" nocase
        $file_access2 = "fopen" nocase
        $file_access3 = "readfile" nocase
        $file_access4 = "read(" nocase
        $sensitive1 = "password" nocase
        $sensitive2 = "credit" nocase
        $sensitive3 = "account" nocase
        $sensitive4 = "ssn" nocase
        $sensitive5 = "social security" nocase
        $exfil1 = "upload" nocase
        $exfil2 = "send" nocase
        $exfil3 = "post" nocase
        $exfil4 = "put" nocase
        $exfil5 = "transfer" nocase
        
    condition:
        (2 of ($file_access*)) and 
        (1 of ($sensitive*)) and
        (1 of ($exfil*))
}
'''
        # Write the example rules to files
        with open(os.path.join(directory, 'ransomware.yar'), 'w') as f:
            f.write(ransomware_rule)
            
        with open(os.path.join(directory, 'backdoor.yar'), 'w') as f:
            f.write(backdoor_rule)
            
        with open(os.path.join(directory, 'data_theft.yar'), 'w') as f:
            f.write(data_theft_rule)
            
        logger.info(f"Created example YARA rules in {directory}")
        
    def load_rules(self):
        """
        Load and compile all YARA rules from the rules directory.
        """
        logger.info(f"Loading YARA rules from {self.rules_directory}")
        
        # Check if directory exists
        if not os.path.exists(self.rules_directory):
            logger.warning(f"YARA rules directory {self.rules_directory} does not exist")
            return
            
        # Walk through all subdirectories to find rule files
        rule_files = []
        for root, _, files in os.walk(self.rules_directory):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    rule_files.append(os.path.join(root, file))
                    
        if not rule_files:
            logger.warning("No YARA rule files found")
            return
            
        # Load each rule file
        for rule_file in rule_files:
            try:
                # Derive category from directory structure
                rel_path = os.path.relpath(rule_file, self.rules_directory)
                category = os.path.dirname(rel_path).replace('\\', '/').strip('/')
                if not category:
                    category = 'default'
                    
                # Compile the rule
                compiled_rule = yara.compile(rule_file)
                
                # Extract rule names and metadata
                rule_source = open(rule_file, 'r').read()
                rule_names, rule_metas = self._extract_rule_metadata(rule_source)
                
                # Store the compiled rule
                rule_key = f"{category}/{os.path.basename(rule_file)}"
                self.rules[rule_key] = compiled_rule
                
                # Store metadata for each rule in the file
                for i, rule_name in enumerate(rule_names):
                    meta = rule_metas[i] if i < len(rule_metas) else {}
                    self.rule_metadata[f"{rule_key}/{rule_name}"] = {
                        "name": rule_name,
                        "category": category,
                        "file": os.path.basename(rule_file),
                        "path": rule_file,
                        "meta": meta
                    }
                    
                logger.info(f"Loaded YARA rule: {rule_key} ({len(rule_names)} rules)")
                
            except Exception as e:
                logger.error(f"Error loading YARA rule {rule_file}: {str(e)}")
                
        logger.info(f"Loaded {len(self.rules)} YARA rule files with {len(self.rule_metadata)} individual rules")
    
    def _extract_rule_metadata(self, rule_source: str) -> tuple:
        """
        Extract rule names and metadata from YARA rule source.
        
        Args:
            rule_source: YARA rule source code
            
        Returns:
            Tuple of (rule_names, rule_metas)
        """
        rule_names = []
        rule_metas = []
        
        # Extract rule names
        name_pattern = re.compile(r'rule\s+(\w+)\s*{')
        for match in name_pattern.finditer(rule_source):
            rule_names.append(match.group(1))
            
        # Extract metadata blocks for each rule
        meta_pattern = re.compile(r'meta:\s*(.+?)\s*strings:', re.DOTALL)
        for match in meta_pattern.finditer(rule_source):
            meta_block = match.group(1)
            meta_dict = {}
            
            # Parse each metadata field
            for line in meta_block.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'").strip()
                    if key and value:
                        meta_dict[key] = value
                        
            rule_metas.append(meta_dict)
            
        return rule_names, rule_metas
    
    def match_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Match a file against all loaded YARA rules.
        
        Args:
            file_path: Path to the file to match
            
        Returns:
            List of match results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []
            
        matches = []
        
        # Match against each rule set
        for rule_key, compiled_rule in self.rules.items():
            try:
                rule_matches = compiled_rule.match(file_path)
                
                for match in rule_matches:
                    rule_id = f"{rule_key}/{match.rule}"
                    metadata = self.rule_metadata.get(rule_id, {})
                    
                    # Extract severity from metadata or default to medium
                    meta = metadata.get('meta', {})
                    severity = meta.get('severity', 'medium').lower()
                    
                    # Extract MITRE ATT&CK info
                    mitre_tactic = meta.get('mitre_tactic', '')
                    mitre_technique = meta.get('mitre_technique', '')
                    
                    # Extract tags
                    tags = meta.get('tags', '').split(',')
                    tags = [tag.strip() for tag in tags if tag.strip()]
                    
                    # Create match result
                    match_result = {
                        "name": f"YARA Detection: {match.rule}",
                        "description": meta.get('description', f"File matched YARA rule: {match.rule}"),
                        "severity": severity,
                        "detection_type": "yara",
                        "rule_id": rule_id,
                        "category": metadata.get('category', 'default'),
                        "matched_strings": [str(s) for s in match.strings],
                        "tags": tags,
                        "confidence": 0.9,  # YARA rules have high confidence
                        "mitre_tactics": [mitre_tactic] if mitre_tactic else [],
                        "mitre_techniques": [mitre_technique] if mitre_technique else []
                    }
                    
                    matches.append(match_result)
                    
            except Exception as e:
                logger.error(f"Error matching file {file_path} against rule {rule_key}: {str(e)}")
                
        return matches
    
    def match_content(self, content: Union[str, bytes], filename: str = None) -> List[Dict[str, Any]]:
        """
        Match content against all loaded YARA rules.
        
        Args:
            content: Content to match (string or bytes)
            filename: Optional filename for reference
            
        Returns:
            List of match results
        """
        if isinstance(content, str):
            content = content.encode('utf-8')
            
        matches = []
        
        # Match against each rule set
        for rule_key, compiled_rule in self.rules.items():
            try:
                rule_matches = compiled_rule.match(data=content)
                
                for match in rule_matches:
                    rule_id = f"{rule_key}/{match.rule}"
                    metadata = self.rule_metadata.get(rule_id, {})
                    
                    # Extract severity from metadata or default to medium
                    meta = metadata.get('meta', {})
                    severity = meta.get('severity', 'medium').lower()
                    
                    # Extract MITRE ATT&CK info
                    mitre_tactic = meta.get('mitre_tactic', '')
                    mitre_technique = meta.get('mitre_technique', '')
                    
                    # Extract tags
                    tags = meta.get('tags', '').split(',')
                    tags = [tag.strip() for tag in tags if tag.strip()]
                    
                    # Create match result
                    match_result = {
                        "name": f"YARA Detection: {match.rule}",
                        "description": meta.get('description', f"Content matched YARA rule: {match.rule}"),
                        "severity": severity,
                        "detection_type": "yara",
                        "rule_id": rule_id,
                        "category": metadata.get('category', 'default'),
                        "matched_strings": [str(s) for s in match.strings],
                        "tags": tags,
                        "confidence": 0.9,
                        "mitre_tactics": [mitre_tactic] if mitre_tactic else [],
                        "mitre_techniques": [mitre_technique] if mitre_technique else [],
                        "filename": filename
                    }
                    
                    matches.append(match_result)
                    
            except Exception as e:
                logger.error(f"Error matching content against rule {rule_key}: {str(e)}")
                
        return matches
    
    def add_rule(self, rule_content: str, category: str = 'custom', filename: str = None) -> bool:
        """
        Add a new YARA rule.
        
        Args:
            rule_content: YARA rule content
            category: Category to assign the rule to
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create category directory if it doesn't exist
            category_dir = os.path.join(self.rules_directory, category)
            if not os.path.exists(category_dir):
                os.makedirs(category_dir)
                
            # Generate filename if not provided
            if not filename:
                # Generate a filename based on the first rule name or hash of content
                rule_names, _ = self._extract_rule_metadata(rule_content)
                if rule_names:
                    filename = f"{rule_names[0]}.yar"
                else:
                    content_hash = hashlib.md5(rule_content.encode('utf-8')).hexdigest()[:8]
                    filename = f"rule_{content_hash}.yar"
                    
            # Ensure filename has .yar extension
            if not filename.endswith('.yar') and not filename.endswith('.yara'):
                filename += '.yar'
                
            # Full path to the rule file
            rule_path = os.path.join(category_dir, filename)
            
            # Write the rule to file
            with open(rule_path, 'w') as f:
                f.write(rule_content)
                
            # Compile and validate the rule
            try:
                compiled_rule = yara.compile(rule_path)
                
                # Extract rule names and metadata
                rule_names, rule_metas = self._extract_rule_metadata(rule_content)
                
                # Store the compiled rule
                rule_key = f"{category}/{filename}"
                self.rules[rule_key] = compiled_rule
                
                # Store metadata for each rule in the file
                for i, rule_name in enumerate(rule_names):
                    meta = rule_metas[i] if i < len(rule_metas) else {}
                    self.rule_metadata[f"{rule_key}/{rule_name}"] = {
                        "name": rule_name,
                        "category": category,
                        "file": filename,
                        "path": rule_path,
                        "meta": meta
                    }
                    
                logger.info(f"Added new YARA rule: {rule_key} ({len(rule_names)} rules)")
                return True
                
            except Exception as e:
                logger.error(f"Error compiling new YARA rule: {str(e)}")
                # Remove the file if compilation failed
                os.remove(rule_path)
                return False
                
        except Exception as e:
            logger.error(f"Error adding YARA rule: {str(e)}")
            return False
    
    def remove_rule(self, rule_key: str) -> bool:
        """
        Remove a YARA rule.
        
        Args:
            rule_key: Key of the rule to remove (category/filename format)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if rule_key not in self.rules:
                logger.warning(f"Rule not found: {rule_key}")
                return False
                
            # Get rule file path
            for metadata in self.rule_metadata.values():
                if f"{metadata['category']}/{metadata['file']}" == rule_key:
                    file_path = metadata['path']
                    
                    # Remove the file
                    os.remove(file_path)
                    
                    # Remove from dictionaries
                    del self.rules[rule_key]
                    
                    # Remove all metadata entries for this rule file
                    keys_to_remove = [k for k in self.rule_metadata if k.startswith(f"{rule_key}/")]
                    for k in keys_to_remove:
                        del self.rule_metadata[k]
                        
                    logger.info(f"Removed YARA rule: {rule_key}")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error removing YARA rule {rule_key}: {str(e)}")
            return False
    
    def get_rules(self, category: str = None) -> List[Dict[str, Any]]:
        """
        Get all loaded YARA rules.
        
        Args:
            category: Optional category to filter by
            
        Returns:
            List of rule metadata
        """
        result = []
        
        for rule_id, metadata in self.rule_metadata.items():
            if category is None or metadata['category'] == category:
                result.append({
                    "id": rule_id,
                    "name": metadata['name'],
                    "category": metadata['category'],
                    "file": metadata['file'],
                    "meta": metadata['meta']
                })
                
        return result


class YaraDetector:
    """
    Detector that uses YARA rules to identify threats in files and content.
    """
    
    def __init__(self):
        """Initialize the YARA detector."""
        self.rule_manager = YaraRuleManager()
        
    async def detect_file(self, file_path: str, file_info: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Detect threats in a file using YARA rules.
        
        Args:
            file_path: Path to the file to scan
            file_info: Optional additional file information
            
        Returns:
            Detection result if a threat is found, None otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
            
        # Match against YARA rules
        matches = self.rule_manager.match_file(file_path)
        
        if not matches:
            return None
            
        # Sort matches by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        matches.sort(key=lambda x: severity_order.get(x.get('severity', 'medium'), 2))
        
        # Return the highest severity match
        return matches[0]
        
    async def detect_content(self, content: Union[str, bytes], content_info: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Detect threats in content using YARA rules.
        
        Args:
            content: Content to scan (string or bytes)
            content_info: Optional additional content information
            
        Returns:
            Detection result if a threat is found, None otherwise
        """
        # Match against YARA rules
        filename = content_info.get('filename') if content_info else None
        matches = self.rule_manager.match_content(content, filename)
        
        if not matches:
            return None
            
        # Sort matches by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        matches.sort(key=lambda x: severity_order.get(x.get('severity', 'medium'), 2))
        
        # Return the highest severity match
        return matches[0]