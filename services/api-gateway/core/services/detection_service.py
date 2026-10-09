from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId

from config import settings
from core.database.repositories.detection_repository import DetectionRepository
from core.services import core_engine_client
from core.models.detection import (
    DetectionRule,
    DetectionRuleCreate,
    DetectionRuleUpdate,
)
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)


class DetectionService:
    def __init__(self):
        self.detection_repo = DetectionRepository()

        # Initialize integration client if URL is configured
        self.core_engine_url = settings.CORE_ENGINE_URL

    async def get_rules(self, limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        """Get all detection rules."""
        return await self.detection_repo.find_many({}, limit=limit, skip=skip)

    async def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific detection rule by ID."""
        return await self.detection_repo.find_by_id(rule_id)

    async def get_rule_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a detection rule by name."""
        return await self.detection_repo.find_by_name(name)

    async def create_rule(
        self, rule_data: DetectionRuleCreate, user_id: Optional[str] = None
    ) -> str:
        """Create a new detection rule."""
        try:
            # Check if rule with same name already exists
            if rule_data.name:
                existing_rule = await self.detection_repo.find_by_name(rule_data.name)
                if existing_rule:
                    logger.warning(f"Rule with name '{rule_data.name}' already exists")
                    return str(existing_rule["_id"])

            rule_id = await self.detection_repo.create_rule(rule_data, user_id)
            logger.info(f"Created detection rule with ID: {rule_id}")

            # If core engine integration is configured, deploy rule
            if self.core_engine_url:
                await self._deploy_rule_to_core_engine(rule_id)

            return rule_id
        except Exception as e:
            logger.error(f"Error creating detection rule: {str(e)}")
            raise

    async def update_rule(
        self,
        rule_id: str,
        rule_data: DetectionRuleUpdate,
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update an existing detection rule."""
        try:
            updated_rule = await self.detection_repo.update_rule(
                rule_id, rule_data, user_id
            )
            if updated_rule:
                logger.info(f"Updated detection rule with ID: {rule_id}")

                # If core engine integration is configured, update rule
                if self.core_engine_url:
                    await self._update_rule_in_core_engine(rule_id)

                return updated_rule
            logger.warning(f"Detection rule with ID {rule_id} not found for update")
            return None
        except Exception as e:
            logger.error(f"Error updating detection rule {rule_id}: {str(e)}")
            raise

    async def update_rule_status(
        self, rule_id: str, status: str, user_id: Optional[str] = None
    ) -> bool:
        """Update the status of a detection rule."""
        try:
            valid_statuses = ["enabled", "disabled", "testing"]
            if status not in valid_statuses:
                logger.warning(f"Invalid rule status: {status}")
                return False

            result = await self.detection_repo.update_status(rule_id, status, user_id)
            if result:
                logger.info(f"Updated detection rule {rule_id} status to {status}")

                # If core engine integration is configured, update rule status
                if self.core_engine_url:
                    await self._update_rule_status_in_core_engine(rule_id, status)

                return True
            logger.warning(f"Failed to update detection rule {rule_id} status")
            return False
        except Exception as e:
            logger.error(f"Error updating detection rule {rule_id} status: {str(e)}")
            raise

    async def get_rules_by_type(
        self, rule_type: str, limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Get detection rules by type."""
        return await self.detection_repo.find_by_type(rule_type, limit, skip)

    async def get_rules_by_source(
        self, detection_source: str, limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Get detection rules by source."""
        return await self.detection_repo.find_by_source(detection_source, limit, skip)

    async def get_rules_by_severity(
        self, severity: str, limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Get detection rules by severity."""
        return await self.detection_repo.find_by_severity(severity, limit, skip)

    async def get_rules_by_status(
        self, status: str, limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Get detection rules by status."""
        return await self.detection_repo.find_by_status(status, limit, skip)

    async def get_rules_by_tag(
        self, tag: str, limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Get detection rules by tag."""
        return await self.detection_repo.find_by_tag(tag, limit, skip)

    async def search_rules(
        self, query: str, limit: int = 100, skip: int = 0
    ) -> List[Dict[str, Any]]:
        """Search detection rules by keyword."""
        return await self.detection_repo.search_rules(query, limit, skip)

    async def add_tag_to_rule(self, rule_id: str, tag: str) -> bool:
        """Add a tag to a detection rule."""
        return await self.detection_repo.add_tag(rule_id, tag)

    async def remove_tag_from_rule(self, rule_id: str, tag: str) -> bool:
        """Remove a tag from a detection rule."""
        return await self.detection_repo.remove_tag(rule_id, tag)

    async def update_rule_performance_metrics(
        self, rule_id: str, metrics: Dict[str, Any]
    ) -> bool:
        """Update performance metrics for a detection rule."""
        try:
            result = await self.detection_repo.update_performance_metrics(
                rule_id, metrics
            )
            if result:
                logger.info(f"Updated performance metrics for detection rule {rule_id}")
            else:
                logger.warning(
                    f"Failed to update performance metrics for detection rule {rule_id}"
                )
            return result
        except Exception as e:
            logger.error(
                f"Error updating performance metrics for detection rule {rule_id}: {str(e)}"
            )
            raise

    async def get_detection_status(self) -> Dict[str, Any]:
        """Rule counts from the database, and whether the core engine is reachable."""
        by_status = await self.detection_repo.count_by("status")
        client = core_engine_client.get_core_engine_client()
        reachable = await client.is_healthy() if client else False
        if client is None:
            state = "standalone"
        else:
            state = "active" if reachable else "degraded"
        return {
            "status": state,
            "total_rules": sum(by_status.values()),
            "enabled_rules": by_status.get("enabled", 0),
            "disabled_rules": by_status.get("disabled", 0),
            "testing_rules": by_status.get("testing", 0),
            "core_engine": {"configured": client is not None, "reachable": reachable},
            "last_updated": utcnow(),
        }

    # Integration methods for core engine
    async def _deploy_rule_to_core_engine(self, rule_id: str) -> bool:
        """Deploy a rule to the core detection engine."""
        # This would be implemented with actual API calls to the core engine
        # For now, just log the intent
        logger.info(
            f"Would deploy rule {rule_id} to core engine at {self.core_engine_url}"
        )
        return True

    async def _update_rule_in_core_engine(self, rule_id: str) -> bool:
        """Update a rule in the core detection engine."""
        logger.info(
            f"Would update rule {rule_id} in core engine at {self.core_engine_url}"
        )
        return True

    async def _update_rule_status_in_core_engine(
        self, rule_id: str, status: str
    ) -> bool:
        """Update a rule's status in the core detection engine."""
        logger.info(
            f"Would update rule {rule_id} status to {status} in core engine at {self.core_engine_url}"
        )
        return True
