"""
Playbooks: what to do, step by step, when a kind of threat is found.

A playbook has a trigger (a minimum severity, and tags or ATT&CK techniques), a mode
(automatic, approval or notify) and ordered steps, each a response action on the case's
users, messages or the case itself. When an alert is put in a case, every enabled
playbook it matches runs once for that case, in the background: its actions run or wait
for approval as the mode and the organisation's safety limits say (see
core.services.response_actions). Steps whose connector is not connected are skipped.

Every organisation starts with built-in playbooks for the most common threats, in
approval mode, so nothing happens without a person until an administrator says so.
"""
import asyncio
from typing import Any, Dict, List, Optional, Set

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from core.services import case_service, response_actions
from core.services.response_actions import ActionError, NotConnected
from core.tenancy import scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

MAX_TARGETS = 5  # per step: a case naming more users than this needs a person anyway

BUILT_IN: List[Dict[str, Any]] = [
    {
        "built_in": "account-takeover",
        "name": "Account takeover",
        "description": "Someone may be signed in as one of your people: sign them out everywhere and make them choose a new password.",
        "trigger": {"min_severity": "high", "tags": ["brute-force", "account-compromise", "impossible-travel", "credential-access"], "techniques": ["T1078", "T1110"]},
        "steps": [{"action": "m365.revoke_sessions", "target": "user", "params": {}}, {"action": "m365.require_password_change", "target": "user", "params": {}}],
    },
    {
        "built_in": "phishing",
        "name": "Phishing email",
        "description": "A phishing email reached your people: remove it from every mailbox it is in.",
        "trigger": {"min_severity": "medium", "tags": ["phishing"], "techniques": ["T1566"]},
        "steps": [{"action": "m365.purge_message", "target": "message", "params": {}}],
    },
    {
        "built_in": "ransomware",
        "name": "Ransomware",
        "description": "Signs of ransomware: make the case critical, so it is dealt with within the hour.",
        "trigger": {"min_severity": "high", "tags": ["ransomware"], "techniques": ["T1486", "T1490"]},
        "steps": [{"action": "utdrs.escalate_case", "target": "case", "params": {"priority": "critical"}}],
    },
]

# Playbook runs in progress, kept so they are not garbage-collected before they finish.
_running: Set[asyncio.Task] = set()


def _playbooks():
    return scoped(get_database(), "playbooks")


async def ensure_indexes() -> None:
    await get_database()["playbooks"].create_index(
        [("tenant_id", 1), ("built_in", 1)], unique=True, partialFilterExpression={"built_in": {"$type": "string"}}
    )


async def ensure_built_ins() -> None:
    """Give the current organisation the built-in playbooks it does not have yet."""
    for playbook in BUILT_IN:
        if await _playbooks().find_one({"built_in": playbook["built_in"]}, {"_id": 1}):
            continue
        now = utcnow()
        try:
            await _playbooks().insert_one({**playbook, "enabled": True, "mode": "approval", "created_at": now, "updated_at": now, "last_run_at": None})
        except DuplicateKeyError:
            pass  # another process added it at the same moment


async def list_playbooks() -> List[Dict[str, Any]]:
    await ensure_built_ins()
    return await _playbooks().find().sort([("built_in", -1), ("name", 1)]).to_list(500)


async def get(playbook_id: str) -> Optional[Dict[str, Any]]:
    return await _playbooks().find_one({"_id": ObjectId(playbook_id)}) if ObjectId.is_valid(playbook_id) else None


async def create(data: Dict[str, Any]) -> Dict[str, Any]:
    now = utcnow()
    doc = {**data, "built_in": None, "created_at": now, "updated_at": now, "last_run_at": None}
    doc["_id"] = (await _playbooks().insert_one(doc)).inserted_id
    return doc


async def update(playbook_id: str, changes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(playbook_id):
        return None
    return await _playbooks().find_one_and_update(
        {"_id": ObjectId(playbook_id)}, {"$set": {**changes, "updated_at": utcnow()}}, return_document=ReturnDocument.AFTER
    )


async def delete(playbook_id: str) -> bool:
    """Delete a playbook of the organisation's own. Built-in ones can only be turned off."""
    if not ObjectId.is_valid(playbook_id):
        return False
    result = await _playbooks().delete_one({"_id": ObjectId(playbook_id), "built_in": None})
    return bool(result.deleted_count)


def matches(playbook: Dict[str, Any], alert: Dict[str, Any]) -> bool:
    trigger = playbook.get("trigger") or {}
    order = case_service.PRIORITIES
    if order.index(alert.get("severity") if alert.get("severity") in order else "info") < order.index(trigger.get("min_severity", "medium")):
        return False
    tags = {t.lower() for t in trigger.get("tags") or []}
    techniques = list(trigger.get("techniques") or [])
    if not tags and not techniques:
        return True
    alert_tags = {t.lower() for t in alert.get("tags") or []}
    title = (alert.get("title") or "").lower()
    if tags & alert_tags or any(tag in title for tag in tags):
        return True
    found = case_service._techniques(alert)
    return any(t == wanted or t.startswith(wanted + ".") for t in found for wanted in techniques)


def _targets(step: Dict[str, Any], case: Dict[str, Any]) -> List[str]:
    if step["target"] == "case":
        return [str(case["_id"])]
    return [e["value"] for e in case.get("entities", []) if e["type"] == step["target"]][:MAX_TARGETS]


def _params(step: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    params = dict(step.get("params") or {})
    if step["action"] == "m365.purge_message" and "recipients" not in params:
        params["recipients"] = [e["value"] for e in case.get("entities", []) if e["type"] == "user"]
    return params


async def run(
    playbook: Dict[str, Any], case_id: str, *, actor: Dict[str, Any], alert_id: Optional[str] = None, unattended: bool = False
) -> Dict[str, Any]:
    """Run a playbook's steps against a case. A person running it decides for themselves; on its own, it follows its mode."""
    case = await scoped(get_database(), "cases").find_one({"_id": ObjectId(case_id)}) if ObjectId.is_valid(case_id) else None
    if not case:
        raise ActionError("Case not found")
    about = {"id": str(playbook["_id"]), "name": playbook["name"]}
    actions, skipped = [], []
    for step in playbook["steps"]:
        label = response_actions.CATALOGUE[step["action"]].label
        targets = _targets(step, case)
        if not targets:
            skipped.append(f"{label}: the case has no {step['target']} to act on")
            continue
        for target in targets:
            try:
                actions.append(await response_actions.request(
                    step["action"], {"type": step["target"], "value": target}, _params(step, case), actor=actor, case_id=case_id,
                    alert_id=alert_id, playbook=about, mode=playbook["mode"] if unattended else "automatic", unattended=unattended,
                ))
            except NotConnected as e:
                skipped.append(f"{label}: {e}")
                break  # the same for every target
            except ActionError as e:
                skipped.append(f"{label} ({target}): {e}")
    await _playbooks().update_one({"_id": playbook["_id"]}, {"$set": {"last_run_at": utcnow()}})
    summary = f"Playbook \"{playbook['name']}\": {len(actions)} action{'s' if len(actions) != 1 else ''}"
    if skipped:
        summary += f", {len(skipped)} skipped ({'; '.join(skipped)})"
    await case_service.add_entry(case_id, "playbook", actor, summary, playbook_id=about["id"], actions=[a["id"] for a in actions], skipped=skipped)
    return {"actions": actions, "skipped": skipped}


async def on_alert(alert_id: str) -> None:
    """Run every enabled playbook the alert matches, once for its case."""
    alert = await scoped(get_database(), "alerts").find_one({"_id": ObjectId(alert_id)})
    if not alert or not alert.get("case_id"):
        return
    await ensure_built_ins()
    cases = scoped(get_database(), "cases")
    async for playbook in _playbooks().find({"enabled": True}):
        if not matches(playbook, alert):
            continue
        # Once per case: the first of the case's alerts to match claims it.
        claimed = await cases.update_one(
            {"_id": ObjectId(alert["case_id"]), "playbooks_run": {"$ne": str(playbook["_id"])}},
            {"$addToSet": {"playbooks_run": str(playbook["_id"])}},
        )
        if not claimed.modified_count:
            continue
        try:
            await run(playbook, alert["case_id"], actor={"type": "playbook", "id": str(playbook["_id"]), "name": playbook["name"]},
                      alert_id=alert_id, unattended=True)
        except Exception:
            logger.exception(f"Playbook {playbook['name']} failed for alert {alert_id}")


def start(alert_id: str) -> None:
    """Run the playbooks for a new alert in the background, as the current organisation."""
    task = asyncio.create_task(on_alert(alert_id))  # copies the current tenant with the context
    _running.add(task)
    task.add_done_callback(_running.discard)


async def idle() -> None:
    """Wait for playbook runs in progress to finish (for tests and shutdown)."""
    while _running:
        await asyncio.gather(*list(_running), return_exceptions=True)
