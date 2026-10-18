"""
Detection tuning: analysts' verdicts, suppressions and how good each detector is.

- **Verdicts.** An analyst says whether an alert was a real threat (true positive), a
  mistake (false positive), or real but expected activity (benign). The verdict is kept
  on the alert and as a label: the alert, its detector and the events behind it, which
  the model retraining pipeline reads (GET /tuning/labels).
- **Suppressions.** A suppression (an allow-list entry when it names only an entity)
  stops matching alerts from reaching people: they are kept, with status "suppressed",
  but are put in no case, run no playbook and email nobody. It matches on any of an
  alert's title, its detector and an entity (user, device, address, sender, file,
  message), and only up to a severity: critical alerts get through unless a suppression
  says otherwise. Suppressions expire unless made permanent, and count their hits.
- **Quality.** Per detector: alerts, suppressed alerts and verdicts, and its precision;
  a detector most of whose verdicted alerts were not real threats is called noisy.
"""
from collections import defaultdict
from datetime import timedelta
from typing import Any, AsyncIterator, Dict, List, Optional

from bson import ObjectId
from pymongo import ReturnDocument

from core.database.connection import get_database
from core.services import case_service
from core.tenancy import scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

VERDICTS = ("true_positive", "false_positive", "benign")
# What a verdict does to the alert's status.
STATUS_FOR = {"false_positive": "false_positive", "benign": "closed"}
NOISY_MIN_VERDICTS = 5
NOISY_PRECISION = 0.5
QUALITY_MAX_ALERTS = 50000


def _alerts():
    return scoped(get_database(), "alerts")


def _suppressions():
    return scoped(get_database(), "suppressions")


def _labels():
    return scoped(get_database(), "labels")


async def ensure_indexes() -> None:
    database = get_database()
    await database["suppressions"].create_index([("tenant_id", 1), ("enabled", 1)])
    await database["labels"].create_index([("tenant_id", 1), ("alert_id", 1)], unique=True)
    await database["labels"].create_index([("tenant_id", 1), ("at", -1)])


def detector_of(alert: Dict[str, Any]) -> Dict[str, str]:
    """
    Which detector raised the alert: a detection rule by its id when the alert says,
    otherwise the kind of detection and the alert's title.
    """
    metadata = alert.get("metadata") or {}
    details = metadata.get("details") or {}
    if details.get("rule_source_id"):
        return {"key": f"rule:{details['rule_source_id']}", "name": details.get("rule_name") or alert.get("title") or "Rule"}
    kind = metadata.get("detection_type") or alert.get("type") or "detection"
    return {"key": f"{kind}:{alert.get('title', '')}", "name": alert.get("title") or kind}


async def entities_of(alert: Dict[str, Any]) -> List[Dict[str, str]]:
    event_ids = [ObjectId(e) for e in alert.get("event_ids") or [] if ObjectId.is_valid(e)]
    events = await scoped(get_database(), "events").find({"_id": {"$in": event_ids}}).to_list(50) if event_ids else []
    return case_service.entities_of(alert, events)


def _normalise(entity: Dict[str, str]) -> Dict[str, str]:
    value = entity["value"].strip()
    return {"type": entity["type"], "value": value.lower() if entity["type"] in ("user", "sender") else value}


# ---------------------------------------------------------------------------
# Suppressions

async def create_suppression(data: Dict[str, Any], actor: Dict[str, Any]) -> Dict[str, Any]:
    now = utcnow()
    days = data.pop("expires_in_days", None)
    doc = {
        **data,
        "entity": _normalise(data["entity"]) if data.get("entity") else None,
        "title_contains": (data.get("title_contains") or "").strip() or None,
        "enabled": True,
        "expires_at": now + timedelta(days=days) if days else None,
        "hits": 0,
        "last_hit_at": None,
        "created_by": actor,
        "created_at": now,
        "updated_at": now,
    }
    doc["_id"] = (await _suppressions().insert_one(doc)).inserted_id
    return doc


async def list_suppressions() -> List[Dict[str, Any]]:
    return await _suppressions().find().sort("created_at", -1).to_list(1000)


async def get_suppression(suppression_id: str) -> Optional[Dict[str, Any]]:
    return await _suppressions().find_one({"_id": ObjectId(suppression_id)}) if ObjectId.is_valid(suppression_id) else None


async def update_suppression(suppression_id: str, changes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(suppression_id):
        return None
    if "expires_in_days" in changes:
        days = changes.pop("expires_in_days")
        changes["expires_at"] = utcnow() + timedelta(days=days) if days else None
    return await _suppressions().find_one_and_update(
        {"_id": ObjectId(suppression_id)}, {"$set": {**changes, "updated_at": utcnow()}}, return_document=ReturnDocument.AFTER
    )


async def delete_suppression(suppression_id: str) -> bool:
    if not ObjectId.is_valid(suppression_id):
        return False
    return bool((await _suppressions().delete_one({"_id": ObjectId(suppression_id)})).deleted_count)


def matches(suppression: Dict[str, Any], alert: Dict[str, Any], entities: List[Dict[str, str]]) -> bool:
    order = case_service.PRIORITIES
    severity = alert.get("severity") if alert.get("severity") in order else "medium"
    if order.index(severity) > order.index(suppression.get("max_severity", "high")):
        return False
    if suppression.get("title_contains") and suppression["title_contains"].casefold() not in (alert.get("title") or "").casefold():
        return False
    if suppression.get("detector") and suppression["detector"] != detector_of(alert)["key"]:
        return False
    if suppression.get("entity") and suppression["entity"] not in entities:
        return False
    return True


async def suppress_if_matched(alert_id: str) -> Optional[str]:
    """
    Check a new alert against the organisation's suppressions. When one matches, the
    alert is marked suppressed (naming the suppression) and its id is returned.
    """
    now = utcnow()
    active = await _suppressions().find({"enabled": True, "$or": [{"expires_at": None}, {"expires_at": {"$gt": now}}]}).to_list(1000)
    if not active:
        return None
    alert = await _alerts().find_one({"_id": ObjectId(alert_id)})
    if not alert:
        return None
    entities = await entities_of(alert)
    for suppression in active:
        if matches(suppression, alert, entities):
            await _alerts().update_one(
                {"_id": alert["_id"]}, {"$set": {"status": "suppressed", "suppressed_by": str(suppression["_id"]), "updated_at": now}}
            )
            await _suppressions().update_one({"_id": suppression["_id"]}, {"$inc": {"hits": 1}, "$set": {"last_hit_at": now}})
            return str(suppression["_id"])
    return None


# ---------------------------------------------------------------------------
# Verdicts

async def give_verdict(alert_id: str, verdict: str, note: Optional[str], actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Record an analyst's verdict on an alert, and keep it as a label for retraining."""
    alert = await _alerts().find_one({"_id": ObjectId(alert_id)}) if ObjectId.is_valid(alert_id) else None
    if not alert:
        return None
    now = utcnow()
    feedback = {"verdict": verdict, "note": note, "by": actor, "at": now}
    changes: Dict[str, Any] = {"feedback": feedback, "updated_at": now}
    if verdict in STATUS_FOR and alert.get("status") in ("open", "in_progress", "suppressed"):
        changes["status"] = STATUS_FOR[verdict]
    await _alerts().update_one({"_id": alert["_id"]}, {"$set": changes})

    event_ids = [ObjectId(e) for e in alert.get("event_ids") or [] if ObjectId.is_valid(e)]
    events = await scoped(get_database(), "events").find({"_id": {"$in": event_ids}}, {"tenant_id": 0}).to_list(50) if event_ids else []
    detector = detector_of(alert)
    await _labels().replace_one(
        {"alert_id": alert_id},
        {
            "alert_id": alert_id,
            "verdict": verdict,
            "detector": detector["key"],
            "detection_type": (alert.get("metadata") or {}).get("detection_type") or alert.get("type"),
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "tags": alert.get("tags") or [],
            "techniques": case_service._techniques(alert),
            "engine": (alert.get("metadata") or {}).get("details") or {},
            "events": [{**{k: v for k, v in e.items() if k != "_id"}, "id": str(e["_id"])} for e in events],
            "by": actor,
            "at": now,
        },
        upsert=True,
    )
    if alert.get("case_id"):
        words = {"true_positive": "a real threat", "false_positive": "a false positive", "benign": "expected activity"}[verdict]
        await case_service.add_entry(alert["case_id"], "feedback", actor, f"\"{alert.get('title')}\" marked {words}{': ' + note if note else ''}",
                                     alert_id=alert_id, verdict=verdict)
    updated = await _alerts().find_one({"_id": alert["_id"]})
    entities = await entities_of(updated)
    strong = next((e for e in entities if e["type"] in ("user", "host", "asset", "ip", "sender")), None)
    return {
        "alert": updated,
        # For "suppress alerts like this": prefilled, never applied by itself.
        "suggestion": None if verdict == "true_positive" else {
            "name": f"{alert.get('title')}{' — ' + strong['value'] if strong else ''}"[:100],
            "detector": detector["key"],
            "entity": strong,
            "max_severity": alert.get("severity") if alert.get("severity") in ("info", "low", "medium", "high") else "high",
        },
    }


async def labels(since=None) -> AsyncIterator[Dict[str, Any]]:
    query = {"at": {"$gte": since}} if since else {}
    async for label in _labels().find(query, {"_id": 0, "tenant_id": 0}).sort("at", 1):
        yield label


# ---------------------------------------------------------------------------
# Quality

async def quality(days: int) -> List[Dict[str, Any]]:
    since = utcnow() - timedelta(days=days)
    alerts = await _alerts().find(
        {"created_at": {"$gte": since}},
        {"title": 1, "type": 1, "status": 1, "feedback.verdict": 1, "metadata.detection_type": 1, "metadata.details.rule_source_id": 1, "metadata.details.rule_name": 1},
    ).to_list(QUALITY_MAX_ALERTS)
    rows: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"alerts": 0, "suppressed": 0, "true_positive": 0, "false_positive": 0, "benign": 0})
    for alert in alerts:
        detector = detector_of(alert)
        row = rows[detector["key"]]
        row.setdefault("name", detector["name"])
        row["alerts"] += 1
        row["suppressed"] += alert.get("status") == "suppressed"
        verdict = (alert.get("feedback") or {}).get("verdict")
        if verdict in VERDICTS:
            row[verdict] += 1
    out = []
    for key, row in rows.items():
        judged = row["true_positive"] + row["false_positive"] + row["benign"]
        precision = round(row["true_positive"] / judged, 2) if judged else None
        out.append({
            "detector": key, **row, "precision": precision,
            "noisy": judged >= NOISY_MIN_VERDICTS and precision is not None and precision < NOISY_PRECISION,
        })
    return sorted(out, key=lambda r: (not r["noisy"], -r["alerts"]))
