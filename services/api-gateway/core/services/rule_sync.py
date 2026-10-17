"""
Keeps the core engine running the rules in the gateway's catalogue.

The gateway's catalogue (edited in the dashboard) is the source of truth. After every
change, and every RULE_SYNC_INTERVAL_SECONDS as a safety net (for an engine that was
down or restarted with an empty database), the gateway compiles the enabled rules it
can and sends the whole set; the engine replaces its gateway-managed rules with it.
The outcome of the last attempt is kept in MongoDB for the detection status.
"""
import asyncio
from typing import Any, Dict, List, Optional

from config import settings
from core.database.connection import get_database
from core.services import tenants
from core.tenancy import current_tenant, scoped, tenant_context
from core.services import core_engine_client
from core.services.rule_compiler import RuleNotSupported, RuleSyntaxError, compile_logic
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

STATE = {"kind": "rule_sync"}
_lock = asyncio.Lock()

# Gateway tags that are MITRE ATT&CK technique ids (T1059, T1059.001) are passed on as such.
def _techniques(tags: List[str]) -> List[str]:
    return [t for t in tags if len(t) >= 5 and t[0] == "T" and t[1:5].isdigit()]


def to_engine_rule(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The engine's form of a catalogue rule, or None if the engine cannot run it."""
    try:
        detection = compile_logic(rule.get("logic") or "")
    except (RuleSyntaxError, RuleNotSupported):
        return None
    tags = list(rule.get("tags") or [])
    return {
        "source_id": str(rule["_id"]),
        "name": rule["name"],
        "description": rule.get("description") or "",
        "rule_type": "signature",
        "detection": detection,
        "enabled": rule.get("status") == "enabled",
        "severity": rule.get("severity") or "medium",
        "tags": tags,
        "mitre_techniques": _techniques(tags),
    }


async def sync_rules() -> Optional[Dict[str, Any]]:
    """
    Send the current organisation's runnable, enabled rules to the engine, which keeps
    each organisation's rules apart. None when no engine is configured.
    """
    client = core_engine_client.get_core_engine_client()
    if client is None:
        return None

    tenant_id = current_tenant()
    async with _lock:
        rules = await scoped(get_database(), "detection_rules").find({"status": "enabled"}).to_list(None)
        engine_rules = [r for r in map(to_engine_rule, rules) if r]
        state: Dict[str, Any] = {"attempted_at": utcnow(), "rules_sent": len(engine_rules)}
        try:
            result = await client.replace_managed_rules(tenant_id, engine_rules)
            state.update(ok=True, error=None, succeeded_at=state["attempted_at"], removed=result.get("removed", 0))
            logger.info(f"Sent {len(engine_rules)} rules to the core engine")
        except core_engine_client.CoreEngineError as e:
            state.update(ok=False, error=str(e))
            logger.warning(f"Could not send rules to the core engine: {e}")
        await scoped(get_database(), "gateway_state").update_one(STATE, {"$set": state}, upsert=True)
        return state


async def last_sync() -> Optional[Dict[str, Any]]:
    return await scoped(get_database(), "gateway_state").find_one(STATE, {"_id": 0, "kind": 0, "tenant_id": 0})


async def sync_all_tenants() -> None:
    for tenant_id in await tenants.all_ids():
        with tenant_context(tenant_id):
            await sync_rules()


async def sync_periodically() -> None:
    """Run for the life of the process: sync now, then every RULE_SYNC_INTERVAL_SECONDS."""
    while True:
        try:
            await sync_all_tenants()
        except Exception as e:  # never let the loop die
            logger.error(f"Rule sync failed: {e}")
        await asyncio.sleep(settings.RULE_SYNC_INTERVAL_SECONDS)
