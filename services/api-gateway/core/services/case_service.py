"""
Cases: alerts about the same thing, grouped so they are worked once.

An alert joins an open case from the last GROUP_WINDOW that shares one of its strong
entities (the same user, device, source address, email sender or file); otherwise it
starts a case. Strong entities only: grouping on a destination address would join
everything that talks to one busy server. A case takes the highest priority of its
alerts and is due within that priority's SLA. Its timeline records everything that
happens to it. Resolving, closing or marking a case a false positive does the same to
its alerts that are still open.
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId
from pymongo import ReturnDocument

from core.database.connection import get_database
from core.tenancy import scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

GROUP_WINDOW = timedelta(hours=24)
PRIORITIES = ["info", "low", "medium", "high", "critical"]
SLA = {"critical": timedelta(hours=1), "high": timedelta(hours=4), "medium": timedelta(hours=24), "low": timedelta(hours=72), "info": timedelta(days=7)}
OPEN = ["open", "investigating", "contained"]
# What closing a case does to its alerts that are still open.
ALERT_STATUS_FOR = {"resolved": "resolved", "false_positive": "false_positive", "closed": "closed"}

# Event fields that name a strong entity, by entity type.
ENTITY_FIELDS = {
    "user": ["user_id", "user", "username", "account", "recipient"],
    "host": ["hostname", "host", "computer_name", "device"],
    "ip": ["source_ip", "src_ip"],
    "sender": ["sender", "from", "sender_address"],
    "file_hash": ["sha256", "md5", "file_hash"],
}

# ATT&CK techniques, in words, for explanations.
TECHNIQUES = {
    "T1110": "password guessing (brute force)",
    "T1078": "use of a valid account",
    "T1566": "phishing",
    "T1059": "running commands or scripts",
    "T1059.001": "PowerShell commands",
    "T1490": "deleting backups so files cannot be recovered (a ransomware step)",
    "T1486": "encrypting files (ransomware)",
    "T1046": "scanning the network for services",
    "T1071": "command-and-control traffic",
    "T1071.004": "command-and-control over DNS",
    "T1048": "copying data out over an unusual channel",
    "T1567.002": "uploading data to cloud storage",
    "T1190": "exploiting an internet-facing application",
    "T1498": "flooding the network (denial of service)",
    "T1595": "probing from outside (active scanning)",
    "T1021.002": "moving between computers over file shares",
    "T1210": "exploiting other computers on the network",
    "T1203": "exploiting software on a computer",
}
STEPS_BY_TACTIC_HINT = {
    "phishing": ["Remove the message from every mailbox it reached", "Ask anyone who clicked a link or opened an attachment to report it", "Reset the password of anyone who entered it"],
    "ransomware": ["Disconnect the affected computer from the network now", "Check that backups are intact and offline", "Do not pay; contact your incident response contact"],
    "brute-force": ["Check whether any attempt succeeded", "Block the source address if it is not yours", "Make sure the account has multi-factor authentication"],
    "exfiltration": ["Find what data was sent and where", "Revoke the account's sessions and change its password", "Block the destination if it is not a service you use"],
}
DEFAULT_STEPS = ["Look at the events behind each alert", "Decide whether it is expected activity; if so, mark it a false positive", "If not, contain it: disable the account or isolate the device involved"]


def _cases():
    return scoped(get_database(), "cases")


def _alerts():
    return scoped(get_database(), "alerts")


def _events():
    return scoped(get_database(), "events")


async def ensure_indexes() -> None:
    cases = get_database()["cases"]
    await cases.create_index([("tenant_id", 1), ("status", 1), ("last_seen", -1)])
    await cases.create_index([("tenant_id", 1), ("entities.type", 1), ("entities.value", 1)])


def entities_of(alert: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    found: Dict[Tuple[str, str], None] = {}
    for asset_id in alert.get("asset_ids") or []:
        found[("asset", str(asset_id))] = None
    for event in events:
        if event.get("asset_id"):
            found[("asset", str(event["asset_id"]))] = None
        fields = {**(event.get("raw_data") or {}), **{k: event[k] for k in ("user_id", "source_ip") if event.get(k)}}
        for kind, names in ENTITY_FIELDS.items():
            for name in names:
                value = fields.get(name)
                if isinstance(value, (str, int)) and str(value).strip():
                    found[(kind, str(value).strip().lower() if kind in ("sender", "user") else str(value).strip())] = None
    return [{"type": t, "value": v} for t, v in found]


def _priority(*levels: Optional[str]) -> str:
    known = [level for level in levels if level in PRIORITIES]
    return max(known, key=PRIORITIES.index) if known else "medium"


def _techniques(alert: Dict[str, Any]) -> List[str]:
    details = (alert.get("metadata") or {}).get("details") or {}
    techniques = list(details.get("mitre_techniques") or [])
    techniques += [t for t in alert.get("tags") or [] if len(t) >= 5 and t[0] == "T" and t[1:5].isdigit()]
    return sorted(set(techniques))


def _entry(kind: str, actor: Optional[Dict[str, Any]] = None, text: Optional[str] = None, **data) -> Dict[str, Any]:
    return {"at": utcnow(), "kind": kind, "actor": actor, "text": text, "data": data}


async def attach_alert(alert_id: str) -> Optional[str]:
    """Put a new alert in a case: an open one about the same entity, or a new one. Returns the case id."""
    alert = await _alerts().find_one({"_id": ObjectId(alert_id)})
    if not alert:
        return None
    event_ids = [ObjectId(e) for e in alert.get("event_ids") or [] if ObjectId.is_valid(e)]
    events = await _events().find({"_id": {"$in": event_ids}}).to_list(50) if event_ids else []
    entities = entities_of(alert, events)
    # When the alert was raised: now for a new alert, earlier for one from before cases.
    now = alert.get("created_at") or utcnow()
    priority = _priority(alert.get("severity"))
    techniques = _techniques(alert)
    added = {**_entry("alert_added", text=alert.get("title"), alert_id=alert_id, severity=alert.get("severity")), "at": now}

    case = None
    if entities:
        case = await _cases().find_one(
            {"status": {"$in": OPEN}, "last_seen": {"$gte": now - GROUP_WINDOW}, "entities": {"$elemMatch": {"$or": entities}}},
            sort=[("last_seen", -1)],
        )

    if case:
        new_priority = _priority(case["priority"], priority)
        update: Dict[str, Any] = {
            "$addToSet": {"alert_ids": alert_id, "entities": {"$each": entities}, "techniques": {"$each": techniques}},
            "$set": {"last_seen": max(case["last_seen"], now), "updated_at": utcnow(), "priority": new_priority,
                     "due_at": min(case["due_at"], case["created_at"] + SLA[new_priority])},
            "$push": {"timeline": added},
        }
        await _cases().update_one({"_id": case["_id"]}, update)
        case_id = str(case["_id"])
    else:
        names = [e["value"] for e in entities if e["type"] in ("user", "host", "sender")][:1]
        result = await _cases().insert_one({
            "title": f"{alert.get('title')}{' — ' + names[0] if names else ''}",
            "status": "open",
            "priority": priority,
            "owner_id": None,
            "alert_ids": [alert_id],
            "entities": entities,
            "techniques": techniques,
            "first_seen": now,
            "last_seen": now,
            "created_at": now,
            "updated_at": now,
            "due_at": now + SLA[priority],
            "timeline": [{**_entry("created", text="Opened for this alert"), "at": now}, added],
        })
        case_id = str(result.inserted_id)
    await _alerts().update_one({"_id": alert["_id"]}, {"$set": {"case_id": case_id}})
    return case_id


async def group_existing_alerts(limit: int = 5000) -> int:
    """
    Put the current organisation's open alerts that have no case, from before cases
    existed, into cases, oldest first. Runs at start-up; does nothing once done.
    """
    alerts = await _alerts().find(
        {"case_id": {"$exists": False}, "status": {"$in": ["open", "in_progress"]}}, {"_id": 1}
    ).sort("created_at", 1).to_list(limit)
    for alert in alerts:
        await attach_alert(str(alert["_id"]))
    return len(alerts)


def explain(case: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    titles = sorted({a.get("title", "") for a in alerts if a.get("title")})
    who = [e["value"] for e in case.get("entities", []) if e["type"] in ("user", "host", "sender", "asset")][:3]
    techniques = [TECHNIQUES.get(t) or TECHNIQUES.get(t.split(".")[0]) for t in case.get("techniques", [])]
    techniques = [t for t in dict.fromkeys(techniques) if t]
    count = len(alerts)
    what = f"{count} alert{'s' if count != 1 else ''}"
    what += f" ({'; '.join(titles[:3])}{'; …' if len(titles) > 3 else ''})" if titles else ""
    what += f" involving {', '.join(who)}" if who else ""
    what += f", between {case['first_seen']:%d %b %H:%M} and {case['last_seen']:%d %b %H:%M} UTC." if count > 1 else f", at {case['first_seen']:%d %b %H:%M} UTC."
    why = (
        f"It looks like {', and '.join(techniques[:2])}." if techniques
        else "The detectors flagged it as unusual or matching a known threat pattern."
    )
    why += {"critical": " Treat it as urgent: act within the hour.", "high": " Act on it today, within four hours.",
            "medium": " Look at it within a day.", "low": " Review it when you can, within three days."}.get(case["priority"], "")
    tags = {t.lower() for a in alerts for t in a.get("tags") or []}
    hint = next((h for h in STEPS_BY_TACTIC_HINT if h in tags or any(h in (a.get("title") or "").lower() for a in alerts)), None)
    if not hint and any("T1566" in t for t in case.get("techniques", [])):
        hint = "phishing"
    if not hint and any(t.startswith(("T1490", "T1486")) for t in case.get("techniques", [])):
        hint = "ransomware"
    return {"what_happened": what, "why_it_matters": why, "next_steps": STEPS_BY_TACTIC_HINT.get(hint, DEFAULT_STEPS)}


def present(case: Dict[str, Any], alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """A case as the API returns it: whether it is overdue, and its explanation when the alerts are given."""
    out = dict(case)
    due = case["due_at"]
    out["breached"] = case["status"] in OPEN and due < utcnow()
    if alerts is not None:
        out["explanation"] = explain(case, alerts)
    return out


async def list_cases(query: Dict[str, Any], limit: int, skip: int) -> List[Dict[str, Any]]:
    cursor = _cases().find(query, {"timeline": 0}).sort("last_seen", -1).skip(skip).limit(limit)
    return [present({**c, "timeline": []}) for c in await cursor.to_list(limit)]


async def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(case_id):
        return None
    case = await _cases().find_one({"_id": ObjectId(case_id)})
    if not case:
        return None
    alerts = await _alerts().find({"_id": {"$in": [ObjectId(a) for a in case["alert_ids"] if ObjectId.is_valid(a)]}}).to_list(500)
    return present(case, alerts)


async def update_case(case_id: str, changes: Dict[str, Any], actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(case_id):
        return None
    case = await _cases().find_one({"_id": ObjectId(case_id)})
    if not case:
        return None
    now = utcnow()
    entries, fields = [], {}
    for field, kind in (("status", "status_changed"), ("priority", "priority_changed"), ("owner_id", "owner_changed"), ("title", "title_changed")):
        if field in changes and changes[field] != case.get(field):
            fields[field] = changes[field]
            entries.append(_entry(kind, actor, before=case.get(field), after=changes[field]))
    if not fields:
        return await get_case(case_id)
    if "priority" in fields:
        fields["due_at"] = case["created_at"] + SLA[fields["priority"]]
    await _cases().update_one({"_id": case["_id"]}, {"$set": {**fields, "updated_at": now}, "$push": {"timeline": {"$each": entries}}})

    alert_status = ALERT_STATUS_FOR.get(fields.get("status"))
    if alert_status:
        result = await _alerts().update_many(
            {"_id": {"$in": [ObjectId(a) for a in case["alert_ids"]]}, "status": {"$in": ["open", "in_progress"]}},
            {"$set": {"status": alert_status, "updated_at": now}},
        )
        if result.modified_count:
            await _cases().update_one({"_id": case["_id"]}, {"$push": {"timeline": _entry(
                "alerts_updated", actor, text=f"{result.modified_count} open alert{'s' if result.modified_count != 1 else ''} set to {alert_status.replace('_', ' ')}",
                status=alert_status, count=result.modified_count)}})
    return await get_case(case_id)


async def add_note(case_id: str, text: str, actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(case_id):
        return None
    result = await _cases().update_one(
        {"_id": ObjectId(case_id)}, {"$push": {"timeline": _entry("note", actor, text)}, "$set": {"updated_at": utcnow()}}
    )
    return await get_case(case_id) if result.matched_count else None


async def evidence(case_id: str) -> Optional[Dict[str, Any]]:
    case = await get_case(case_id)
    if not case:
        return None
    alerts = await _alerts().find({"_id": {"$in": [ObjectId(a) for a in case["alert_ids"] if ObjectId.is_valid(a)]}}).sort("created_at", 1).to_list(500)
    event_ids = {ObjectId(e) for a in alerts for e in a.get("event_ids") or [] if ObjectId.is_valid(e)}
    events = await _events().find({"_id": {"$in": list(event_ids)}}).sort("timestamp", 1).to_list(1000)
    for item in alerts + events:
        item["id"] = str(item.pop("_id"))
        item.pop("tenant_id", None)
    return {"alerts": alerts, "events": events, "entities": case["entities"]}
