"""
Predefined detection rules for the UTDRS core engine.
These rules are loaded during startup and can be used for signature-based detection.
"""
from typing import List, Dict, Any
import json
import os
from utils.logger import get_logger

logger = get_logger(__name__)

def get_predefined_rules() -> List[Dict[str, Any]]:
    """
    Get a list of predefined detection rules.
    
    Returns:
        List of rule dictionaries
    """
    return [
        # Authentication Rules
        {
            "name": "Multiple Failed Login Attempts",
            "description": "Detects multiple failed login attempts for the same user within a short time period",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "authentication",
                    "data.status": "failed"
                }
            },
            "enabled": True,
            "severity": "medium",
            "tags": ["authentication", "brute-force"],
            "mitre_tactics": ["TA0006"],  # Credential Access
            "mitre_techniques": ["T1110"]  # Brute Force
        },
        {
            "name": "Admin Account Usage",
            "description": "Detects usage of administrator accounts, which should be monitored",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "authentication",
                    "data.user_type": "admin"
                }
            },
            "enabled": True,
            "severity": "low",
            "tags": ["authentication", "admin"],
            "mitre_tactics": ["TA0004"],  # Privilege Escalation
            "mitre_techniques": ["T1078"]  # Valid Accounts
        },
        
        # Network Rules
        {
            "name": "Connection to Known C2 Server",
            "description": "Detects network connections to known command and control servers",
            "rule_type": "signature",
            "detection": {
                "condition_type": "OR",
                "conditions": {
                    "event_type": "network",
                    "data.dst_ip": ["192.168.0.1", "10.0.0.1"]  # Example IPs, would be a longer list in production
                }
            },
            "enabled": True,
            "severity": "critical",
            "tags": ["network", "c2", "malware"],
            "mitre_tactics": ["TA0011"],  # Command and Control
            "mitre_techniques": ["T1071"]  # Application Layer Protocol
        },
        {
            "name": "DNS Query to Suspicious Domain",
            "description": "Detects DNS queries to known malicious or suspicious domains",
            "rule_type": "signature",
            "detection": {
                "condition_type": "OR",
                "conditions": {
                    "event_type": "dns",
                    "data.domain": ["malicious.com", "evil.net"]  # Example domains, would be a longer list in production
                }
            },
            "enabled": True,
            "severity": "high",
            "tags": ["network", "dns", "malware"],
            "mitre_tactics": ["TA0011"],  # Command and Control
            "mitre_techniques": ["T1071.004"]  # Application Layer Protocol: DNS
        },
        
        # File & Process Rules
        {
            "name": "Suspicious Process Execution",
            "description": "Detects execution of processes commonly used for malicious purposes",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "process",
                    "data.process_name": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]
                }
            },
            "enabled": True,
            "severity": "medium",
            "tags": ["process", "execution"],
            "mitre_tactics": ["TA0002"],  # Execution
            "mitre_techniques": ["T1059"]  # Command and Scripting Interpreter
        },
        {
            "name": "Suspicious PowerShell Command",
            "description": "Detects PowerShell commands with encoded or obfuscated content",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "process",
                    "data.process_name": "powershell.exe",
                    "data.command_line": "regex:.*(encodedcommand|enc).*"
                }
            },
            "enabled": True,
            "severity": "high",
            "tags": ["process", "powershell", "obfuscation"],
            "mitre_tactics": ["TA0002"],  # Execution
            "mitre_techniques": ["T1059.001"]  # Command and Scripting Interpreter: PowerShell
        },
        {
            "name": "Sensitive File Access",
            "description": "Detects access to sensitive system files or configuration files",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "file",
                    "data.filepath": r"regex:.*(passwd|shadow|\.ssh|\.aws|\.config).*"
                }
            },
            "enabled": True,
            "severity": "medium",
            "tags": ["file", "sensitive-data"],
            "mitre_tactics": ["TA0006"],  # Credential Access
            "mitre_techniques": ["T1552"]  # Unsecured Credentials
        },
        
        # Endpoint Security Rules
        {
            "name": "Security Service Disabled",
            "description": "Detects when security services like antivirus or firewall are disabled",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "system",
                    "data.action": "disable",
                    "data.service_name": "regex:.*(defender|firewall|security|protection).*"
                }
            },
            "enabled": True,
            "severity": "high",
            "tags": ["system", "defense-evasion"],
            "mitre_tactics": ["TA0005"],  # Defense Evasion
            "mitre_techniques": ["T1562"]  # Impair Defenses
        },
        {
            "name": "New User Account Created",
            "description": "Detects creation of new user accounts, which should be monitored",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "user",
                    "data.action": "create"
                }
            },
            "enabled": True,
            "severity": "low",
            "tags": ["user", "account-creation"],
            "mitre_tactics": ["TA0003"],  # Persistence
            "mitre_techniques": ["T1136"]  # Create Account
        },
        
        # Data Exfiltration Rules
        {
            "name": "Large File Upload",
            "description": "Detects upload of unusually large files to external services",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "network",
                    "data.direction": "outbound",
                    "data.bytes_sent": {"gt": 10000000}  # 10MB
                }
            },
            "enabled": True,
            "severity": "medium",
            "tags": ["network", "data-exfiltration"],
            "mitre_tactics": ["TA0010"],  # Exfiltration
            "mitre_techniques": ["T1048"]  # Exfiltration Over Alternative Protocol
        },
        {
            "name": "Email With Attachment Sent to External Domain",
            "description": "Detects emails with attachments sent to external domains",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "email",
                    "data.direction": "outbound",
                    "data.has_attachment": True,
                    "data.recipient_domain": "regex:^(?!company\\.com).*$"  # Not company.com
                }
            },
            "enabled": True,
            "severity": "low",
            "tags": ["email", "data-exfiltration"],
            "mitre_tactics": ["TA0010"],  # Exfiltration
            "mitre_techniques": ["T1048.003"]  # Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
        },
        
        # Malware & Ransomware Rules
        {
            "name": "Ransomware File Operations",
            "description": "Detects file operations typical of ransomware (mass renaming/encryption)",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "file",
                    "data.operation": ["rename", "write", "create"],
                    "data.file_extension": ["crypto", "locked", "encrypted", "enc", "crypt"]
                }
            },
            "enabled": True,
            "severity": "critical",
            "tags": ["file", "ransomware"],
            "mitre_tactics": ["TA0040"],  # Impact
            "mitre_techniques": ["T1486"]  # Data Encrypted for Impact
        },
        {
            "name": "Known Malware Hash Detected",
            "description": "Detects files with hashes matching known malware",
            "rule_type": "signature",
            "detection": {
                "condition_type": "AND",
                "conditions": {
                    "event_type": "file",
                    "data.file_hash": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]  # Example hash, would be a longer list in production
                }
            },
            "enabled": True,
            "severity": "critical",
            "tags": ["file", "malware"],
            "mitre_tactics": ["TA0002"],  # Execution
            "mitre_techniques": ["T1204"]  # User Execution
        }
    ]

def save_rules_to_file(output_dir: str = "core/rules/predefined"):
    """
    Save predefined rules to JSON files.
    
    Args:
        output_dir: Directory to save the rules to
    """
    predefined_rules = get_predefined_rules()
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Save rules by category
    rule_categories = {}
    
    for rule in predefined_rules:
        # Determine category from tags
        category = "other"
        for tag in rule.get("tags", []):
            if tag in ["authentication", "network", "file", "process", "email", "user", "system"]:
                category = tag
                break
                
        if category not in rule_categories:
            rule_categories[category] = []
            
        rule_categories[category].append(rule)
        
    # Save each category to a file
    for category, rules in rule_categories.items():
        filename = os.path.join(output_dir, f"{category}_rules.json")
        with open(filename, "w") as f:
            json.dump(rules, f, indent=2)
            
    logger.info(f"Saved {len(predefined_rules)} rules to {output_dir}")
    
if __name__ == "__main__":
    # When run directly, save rules to files
    save_rules_to_file()