"""HTTP client for the UTDRS core detection engine."""
from typing import Any, Dict, List, Optional

import httpx

from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)


class CoreEngineError(Exception):
    """The core engine could not be reached or returned an error."""


class CoreEngineClient:
    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: float = 10.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-Internal-Token": token} if token else {}
        self.timeout = timeout
        self.transport = transport

    async def analyse_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send an event to the engine's detection pipeline.

        Returns the engine's alert when it detects a threat, or None for a clean event.
        """
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self.headers,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.post("/detections/process", json=event)
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CoreEngineError(str(exc)) from exc


    async def replace_managed_rules(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make the engine's gateway-managed rules exactly these."""
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self.headers,
                timeout=self.timeout,
                transport=self.transport,
            ) as client:
                response = await client.put("/rules/managed/gateway", json={"rules": rules})
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CoreEngineError(str(exc)) from exc

    async def is_healthy(self) -> bool:
        """Whether the engine answers its health check."""
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=min(self.timeout, 3.0), transport=self.transport
            ) as client:
                response = await client.get("/health")
                return response.status_code == 200
        except httpx.HTTPError:
            return False


def get_core_engine_client() -> Optional[CoreEngineClient]:
    """The configured client, or None when no core engine is configured."""
    if not settings.CORE_ENGINE_URL:
        return None
    return CoreEngineClient(
        settings.CORE_ENGINE_URL,
        token=settings.INTERNAL_API_TOKEN,
        timeout=settings.CORE_ENGINE_TIMEOUT_SECONDS,
    )
