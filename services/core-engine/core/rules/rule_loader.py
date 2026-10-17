from typing import Dict, List, Any, Optional
from core.database.repositories.rule_repository import RuleRepository
from core.rules.predefined.rules import get_predefined_rules
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)


class RuleManager:
    def __init__(self):
        self.rule_repository = RuleRepository()

    async def load_predefined_rules(self) -> int:
        """
        Store each predefined rule that is not stored yet, matched by name, so rules
        edited or disabled through the API are left as they are. Returns how many
        were added.
        """
        added = 0
        for rule in get_predefined_rules():
            # Built-in rules only: a managed rule may share a built-in rule's name.
            if await self.rule_repository.find_one({"name": rule["name"], "source": {"$exists": False}}):
                continue
            await self.create_rule(dict(rule))
            added += 1
        return added
        
    async def get_rules(self, filters, limit=100, skip=0):
        return await self.rule_repository.find_many(filters, limit, skip)
        
    async def get_rule_by_id(self, rule_id):
        return await self.rule_repository.find_by_id(rule_id)
        
    async def create_rule(self, rule_data):
        # Validate rule before saving
        self._validate_rule(rule_data)
        
        # Add created timestamp
        from datetime import datetime
        rule_data['created_at'] = utcnow()
        rule_data['updated_at'] = utcnow()
        
        # Save to database
        rule_id = await self.rule_repository.insert_one(rule_data)
        return await self.get_rule_by_id(rule_id)
        
    async def update_rule(self, rule_id, rule_data):
        # Validate rule before updating
        self._validate_rule(rule_data)
        
        # Update timestamp
        from datetime import datetime
        rule_data['updated_at'] = utcnow()
        
        # Update in database
        success = await self.rule_repository.update_one(rule_id, rule_data)
        if success:
            return await self.get_rule_by_id(rule_id)
        return None
        
    async def delete_rule(self, rule_id):
        return await self.rule_repository.delete_one(rule_id)

    async def replace_managed_rules(self, source: str, rules: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Make the rules managed by `source` (the API gateway) exactly `rules`: store or
        update each one, matched by its source_id, and remove that source's rules that
        are no longer listed. Built-in rules are not touched. Every rule is validated
        before anything is written, so a bad rule changes nothing.
        """
        for rule in rules:
            self._validate_rule(rule)

        now = utcnow()
        collection = self.rule_repository.collection
        for rule in rules:
            await collection.update_one(
                {"source": source, "source_id": rule["source_id"]},
                {"$set": {**rule, "source": source, "updated_at": now}, "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
        keep = [rule["source_id"] for rule in rules]
        removed = await collection.delete_many({"source": source, "source_id": {"$nin": keep}})
        return {"stored": len(rules), "removed": removed.deleted_count}
        
    def _validate_rule(self, rule_data):
        required_fields = ['name', 'description', 'rule_type', 'detection']
        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"Missing required field: {field}")
                
        valid_rule_types = ['signature', 'anomaly', 'correlation', 'ml']
        if rule_data['rule_type'] not in valid_rule_types:
            raise ValueError(f"Invalid rule type: {rule_data['rule_type']}. Must be one of {valid_rule_types}")
            
        # Validate detection based on rule type
        if rule_data['rule_type'] == 'signature':
            if 'conditions' not in rule_data.get('detection', {}):
                raise ValueError("Signature rules must have detection.conditions defined")
