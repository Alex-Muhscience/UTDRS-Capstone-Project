from typing import Dict, Any, Optional, List
import re
from utils.logger import get_logger
from core.rules.rule_loader import RuleManager

logger = get_logger(__name__)

class SignatureDetector:
    def __init__(self):
        self.rule_manager = RuleManager()
        
    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect threats using signature-based rules.
        
        Args:
            event: The event to analyze
            
        Returns:
            Detection result dict if a rule matches, None otherwise
        """
        # Get all enabled signature rules
        rules = await self.rule_manager.get_rules({
            "rule_type": "signature", 
            "enabled": True
        })
        
        logger.debug(f"Loaded {len(rules)} signature rules for detection")
        
        for rule in rules:
            if await self._match_rule(event, rule):
                logger.info(f"Event matched signature rule: {rule['name']}")
                
                # Extract MITRE ATT&CK information if available
                mitre_tactics = rule.get('mitre_tactics', [])
                mitre_techniques = rule.get('mitre_techniques', [])
                
                return {
                    "name": rule['name'],
                    "description": rule['description'],
                    "severity": rule['severity'],
                    "detection_type": "signature",
                    "rule_id": str(rule.get('_id', '')),
                    "tags": rule.get('tags', []),
                    "mitre_tactics": mitre_tactics,
                    "mitre_techniques": mitre_techniques
                }
                
        return None
        
    async def _match_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """
        Match an event against a rule's conditions.
        
        Args:
            event: The event to check
            rule: The rule to match against
            
        Returns:
            True if the event matches the rule, False otherwise
        """
        try:
            detection = rule.get('detection', {})
            
            # Get condition type - AND is default
            condition_type = detection.get('condition_type', 'AND').upper()
            conditions = detection.get('conditions', {})
            
            # Check for match operator (ALL, ANY)
            if condition_type == 'OR' or condition_type == 'ANY':
                # ANY condition matches (OR)
                for field, matcher in conditions.items():
                    if self._match_field(event, field, matcher):
                        return True
                return False
            else:
                # ALL conditions must match (AND)
                for field, matcher in conditions.items():
                    if not self._match_field(event, field, matcher):
                        return False
                return True
            
        except Exception as e:
            logger.error(f"Error matching rule {rule.get('name')}: {str(e)}")
            return False
    
    def _match_field(self, event: Dict[str, Any], field: str, matcher: Any) -> bool:
        """
        Match a specific field in the event against its expected value or pattern.
        
        Args:
            event: The event containing the field to check
            field: The field to check, can use dot notation for nested fields
            matcher: The matcher pattern, can be a value, list, regex, or condition
            
        Returns:
            True if the field matches, False otherwise
        """
        # Extract field value using dot notation
        value = self._get_nested_value(event, field)
        
        # If we couldn't find the field, no match
        if value is None:
            return False
            
        # Handle different matcher types
        if isinstance(matcher, dict):
            # Matcher is a condition (e.g., {'gt': 100})
            return self._process_condition_matcher(value, matcher)
        elif isinstance(matcher, list):
            # Matcher is a list of possible values
            return value in matcher
        elif isinstance(matcher, str) and matcher.startswith('regex:'):
            # Matcher is a regex pattern
            pattern = matcher[6:]  # Remove 'regex:' prefix
            try:
                return bool(re.match(pattern, str(value)))
            except re.error:
                logger.error(f"Invalid regex pattern: {pattern}")
                return False
        else:
            # Direct value comparison
            return value == matcher
    
    def _process_condition_matcher(self, value: Any, condition: Dict[str, Any]) -> bool:
        """
        Process a condition-based matcher.
        
        Args:
            value: The field value to check
            condition: The condition dict (e.g., {'gt': 100, 'lt': 200})
            
        Returns:
            True if the condition is met, False otherwise
        """
        for op, expected in condition.items():
            if op == 'gt':
                if not (isinstance(value, (int, float)) and value > expected):
                    return False
            elif op == 'lt':
                if not (isinstance(value, (int, float)) and value < expected):
                    return False
            elif op == 'gte':
                if not (isinstance(value, (int, float)) and value >= expected):
                    return False
            elif op == 'lte':
                if not (isinstance(value, (int, float)) and value <= expected):
                    return False
            elif op == 'contains':
                if not (isinstance(value, str) and expected in value):
                    return False
            elif op == 'starts_with':
                if not (isinstance(value, str) and value.startswith(expected)):
                    return False
            elif op == 'ends_with':
                if not (isinstance(value, str) and value.endswith(expected)):
                    return False
            elif op == 'length':
                if not (hasattr(value, '__len__') and len(value) == expected):
                    return False
            elif op == 'not':
                if value == expected:
                    return False
        
        # All conditions passed
        return True
    
    def _get_nested_value(self, event: Dict[str, Any], field: str) -> Any:
        """
        Get a nested value from a dict using dot notation.
        
        Args:
            event: The dict to extract from
            field: The field to extract, using dot notation for nested fields
            
        Returns:
            The field value or None if not found
        """
        if "." not in field:
            return event.get(field)
            
        # Handle nested fields
        current = event
        for part in field.split('.'):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current