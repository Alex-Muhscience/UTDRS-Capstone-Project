"""
Bringing Microsoft 365 data into UTDRS.

Every M365_POLL_INTERVAL_SECONDS, for each organisation that has connected Microsoft 365,
UTDRS fetches from Microsoft Graph what is new since last time:

- **Entra ID sign-ins** (/auditLogs/signIns) become `authentication` events.
- **Directory audit logs** (/auditLogs/directoryAudits) become `audit` events: role
  changes, application consents, security information changes, and so on.
- **Defender and Entra ID Protection alerts** (/security/alerts_v2) are Microsoft's own
  detections, so they become alerts directly (with an event holding Microsoft's record),
  and go through suppressions, cases, playbooks and email like any other alert.

Events keep Microsoft's id (`raw_data.external_id`), and a unique index stores each once,
so overlapping polls are harmless. Each source keeps its own cursor and its own error
(a missing permission stops that source only). Pages are followed up to MAX_PAGES a poll;
Microsoft's throttling (429, Retry-After) is respected. One process polls an organisation
at a time (a lease on its connection).

Sign-ins and audit events go to the core engine like any other event, where the
Microsoft 365 detection rules UTDRS adds to the organisation's catalogue on connecting
look for risky sign-ins, smart lockout, legacy authentication, admin roles granted,
application consents and MFA methods removed.
"""
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from config import settings
from core.database.connection import get_database
from core.models.alert import AlertCreate
from core.models.detection import DetectionRuleCreate
from core.models.event import EventCreate
from core.services import m365, tenants
from core.tenancy import scoped, tenant_context
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

FIRST_LOOK_BACK = timedelta(days=1)
MAX_PAGES = 20
PAGE_SIZE = 500
POLL_LEASE = timedelta(minutes=10)
MAX_RETRY_AFTER_SECONDS = 60
SOURCE = "m365"

DEFENDER_SEVERITY = {"informational": "info", "low": "low", "medium": "medium", "high": "high"}

# Detection rules added to an organisation's catalogue when it connects Microsoft 365.
RULES: List[Dict[str, Any]] = [
    {
        "name": "Microsoft 365: risky sign-in",
        "description": "Entra ID Protection rated a sign-in as medium or high risk: the account may be in someone else's hands.",
        "severity": "high",
        "tags": ["identity", "account-compromise", "T1078"],
        "logic": "source == 'm365' and event_type == 'authentication' and risk_level in ['medium', 'high']",
    },
    {
        "name": "Microsoft 365: account locked by smart lockout",
        "description": "Too many wrong passwords locked the account: someone may be guessing it.",
        "severity": "medium",
        "tags": ["identity", "brute-force", "T1110"],
        "logic": "source == 'm365' and event_type == 'authentication' and error_code == 50053",
    },
    {
        "name": "Microsoft 365: legacy authentication sign-in",
        "description": "A successful sign-in with an old protocol (IMAP, POP, SMTP, ActiveSync) that cannot use multi-factor authentication.",
        "severity": "medium",
        "tags": ["identity", "credential-access", "T1078"],
        "logic": "source == 'm365' and event_type == 'authentication' and status == 'success' and client_app in "
                 "['Exchange ActiveSync', 'IMAP4', 'POP3', 'Authenticated SMTP', 'Other clients']",
    },
    {
        "name": "Microsoft 365: administrator role granted",
        "description": "Someone was made an administrator. Check it was intended: attackers give themselves admin roles to stay in.",
        "severity": "high",
        "tags": ["identity", "privilege-escalation", "T1098.003"],
        "logic": "source == 'm365' and event_type == 'audit' and activity == 'Add member to role' and role matches '(?i)admin'",
    },
    {
        "name": "Microsoft 365: application consent granted",
        "description": "An application was given access to your data. Consent phishing tricks people into granting it to an attacker's app.",
        "severity": "medium",
        "tags": ["identity", "oauth-consent", "T1528"],
        "logic": "source == 'm365' and event_type == 'audit' and activity == 'Consent to application'",
    },
    {
        "name": "Microsoft 365: MFA method removed",
        "description": "A multi-factor authentication method was removed from an account, which makes it easier to take over.",
        "severity": "medium",
        "tags": ["identity", "mfa", "T1556.006"],
        "logic": "source == 'm365' and event_type == 'audit' and activity matches "
                 "'(?i)(deleted security info|delete.*authentication method|disable strong authentication)'",
    },
]


def _time(value: Optional[str]) -> datetime:
    if not value:
        return utcnow()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _graph_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Mapping Microsoft's records to UTDRS events

def sign_in_event(record: Dict[str, Any]) -> EventCreate:
    status = record.get("status") or {}
    ok = status.get("errorCode", 0) == 0
    location = record.get("location") or {}
    device = record.get("deviceDetail") or {}
    upn = (record.get("userPrincipalName") or "").lower()
    app = record.get("appDisplayName") or "an application"
    return EventCreate(
        timestamp=_time(record.get("createdDateTime")),
        event_type="authentication",
        source=SOURCE,
        source_ip=record.get("ipAddress"),
        action="success" if ok else "failure",
        user_id=upn or None,
        description=f"Sign-in by {upn or 'unknown user'} to {app}: " + ("succeeded" if ok else f"failed ({status.get('failureReason') or status.get('errorCode')})"),
        raw_data={
            "external_id": f"signin:{record['id']}",
            "user": upn,
            "source_ip": record.get("ipAddress"),
            "app": record.get("appDisplayName"),
            "client_app": record.get("clientAppUsed"),
            "status": "success" if ok else "failure",
            "error_code": status.get("errorCode", 0),
            "failure_reason": status.get("failureReason"),
            "country": location.get("countryOrRegion"),
            "city": location.get("city"),
            # For impossible travel, which the engine works out between sign-ins.
            "latitude": (location.get("geoCoordinates") or {}).get("latitude"),
            "longitude": (location.get("geoCoordinates") or {}).get("longitude"),
            "risk_level": record.get("riskLevelDuringSignIn"),
            "risk_state": record.get("riskState"),
            "risk_events": record.get("riskEventTypes_v2") or [],
            "conditional_access": record.get("conditionalAccessStatus"),
            "mfa_required": record.get("authenticationRequirement") == "multiFactorAuthentication",
            "interactive": record.get("isInteractive"),
            "device_os": device.get("operatingSystem"),
            "browser": device.get("browser"),
        },
    )


def audit_event(record: Dict[str, Any]) -> EventCreate:
    initiated = record.get("initiatedBy") or {}
    actor = ((initiated.get("user") or {}).get("userPrincipalName") or (initiated.get("app") or {}).get("displayName") or "").lower()
    targets = record.get("targetResources") or []
    target_user = next((t.get("userPrincipalName") for t in targets if t.get("type") == "User" and t.get("userPrincipalName")), None)
    names = [t.get("userPrincipalName") or t.get("displayName") for t in targets if t.get("userPrincipalName") or t.get("displayName")]
    role = None
    for target in targets:
        for prop in target.get("modifiedProperties") or []:
            if prop.get("displayName") in ("Role.DisplayName", "RoleDefinition.DisplayName"):
                role = (prop.get("newValue") or "").strip('"')
    if not role:
        role = next((t.get("displayName") for t in targets if t.get("type") == "Role"), None)
    activity = record.get("activityDisplayName") or ""
    return EventCreate(
        timestamp=_time(record.get("activityDateTime")),
        event_type="audit",
        source=SOURCE,
        action=record.get("result"),
        user_id=(target_user or actor or "").lower() or None,
        description=f"{actor or 'Someone'}: {activity}" + (f" ({', '.join(names[:3])})" if names else ""),
        raw_data={
            "external_id": f"audit:{record['id']}",
            "activity": activity,
            "category": record.get("category"),
            "result": record.get("result"),
            "actor": actor,
            # The person affected, so cases group by them.
            "user": (target_user or "").lower() or None,
            "targets": names,
            "role": role,
        },
    )


def defender_alert(record: Dict[str, Any]) -> Tuple[EventCreate, Dict[str, Any]]:
    """Microsoft's alert, as an event holding its record and the alert UTDRS raises from it."""
    users, hosts, ips = [], [], []
    for evidence in record.get("evidence") or []:
        kind = evidence.get("@odata.type", "")
        if kind.endswith("userEvidence"):
            upn = ((evidence.get("userAccount") or {}).get("userPrincipalName") or "").lower()
            if upn:
                users.append(upn)
        elif kind.endswith("deviceEvidence") and evidence.get("deviceDnsName"):
            hosts.append(evidence["deviceDnsName"])
        elif kind.endswith("ipEvidence") and evidence.get("ipAddress"):
            ips.append(evidence["ipAddress"])
    techniques = list(record.get("mitreTechniques") or [])
    title = record.get("title") or "Microsoft Defender alert"
    event = EventCreate(
        timestamp=_time(record.get("createdDateTime")),
        event_type="security_alert",
        source=SOURCE,
        source_ip=ips[0] if ips else None,
        user_id=users[0] if users else None,
        description=f"{record.get('serviceSource') or 'Microsoft'}: {title}",
        raw_data={
            "external_id": f"alert:{record['id']}",
            "user": users[0] if users else None,
            "hostname": hosts[0] if hosts else None,
            "source_ip": ips[0] if ips else None,
            "users": users, "hosts": hosts, "ips": ips,
            "provider": record.get("serviceSource"),
            "category": record.get("category"),
            "severity": record.get("severity"),
            "status": record.get("status"),
            "url": record.get("alertWebUrl"),
        },
    )
    alert = {
        "title": title,
        "description": record.get("description") or title,
        "severity": DEFENDER_SEVERITY.get((record.get("severity") or "").lower(), "medium"),
        "tags": [t for t in [(record.get("category") or "").lower() or None, "microsoft-defender", *techniques] if t],
        "metadata": {"detection_type": "vendor", "details": {
            "provider": record.get("serviceSource"), "vendor_alert_id": record["id"], "url": record.get("alertWebUrl"),
            "mitre_techniques": techniques, "recommended_actions": record.get("recommendedActions"),
        }},
    }
    return event, alert


# ---------------------------------------------------------------------------
# Fetching

async def _get(client: httpx.AsyncClient, url: str, params: Optional[Dict[str, str]] = None) -> httpx.Response:
    """One Graph request, waiting once if Microsoft says to slow down."""
    response = await client.get(url, params=params)
    if response.status_code == 429:
        await asyncio.sleep(min(int(response.headers.get("Retry-After", "5") or 5), MAX_RETRY_AFTER_SECONDS))
        response = await client.get(url, params=params)
    return response


async def _fetch(client: httpx.AsyncClient, path: str, time_field: str, since: datetime) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Records created since `since`, oldest first, following pages. Returns them and any error."""
    records: List[Dict[str, Any]] = []
    # Oldest first, so a poll cut short by MAX_PAGES resumes where it stopped.
    params = {"$filter": f"{time_field} ge {_graph_time(since)}", "$orderby": f"{time_field} asc", "$top": str(PAGE_SIZE)}
    url: Optional[str] = path
    for _ in range(MAX_PAGES):
        response = await _get(client, url, params)
        if response.status_code in (401, 403):
            return records, "Not allowed: check UTDRS's permissions in Microsoft 365"
        if response.is_error:
            return records, f"Microsoft Graph answered {response.status_code}"
        body = response.json()
        records += body.get("value") or []
        url, params = body.get("@odata.nextLink"), None
        if not url:
            break
    return sorted(records, key=lambda r: r.get(time_field) or ""), None


async def _store_event(event: EventCreate, analyse: bool = True) -> Optional[str]:
    from core.services.detection_pipeline import analyse_event
    from core.services.event_service import EventService

    try:
        event_id = await EventService().create_event(event)
    except DuplicateKeyError:
        return None  # already have it
    if analyse:
        await analyse_event(event_id, event)
    return event_id


async def _poll_source(client, connection, name: str, path: str, time_field: str) -> Tuple[int, Optional[str], Optional[str]]:
    from core.services.alert_service import AlertService

    cursor = (connection.get("cursors") or {}).get(name)
    since = _time(cursor) if cursor else utcnow() - FIRST_LOOK_BACK
    records, error = await _fetch(client, path, time_field, since)
    stored = 0
    for record in records:
        if name == "signins":
            stored += bool(await _store_event(sign_in_event(record)))
        elif name == "audits":
            stored += bool(await _store_event(audit_event(record)))
        else:
            event, alert = defender_alert(record)
            event_id = await _store_event(event, analyse=False)  # Microsoft already decided it is a threat
            if event_id:
                await AlertService().create_alert(
                    AlertCreate(title=alert["title"], description=alert["description"], severity=alert["severity"], source="microsoft-defender",
                                type="vendor", tags=alert["tags"], event_ids=[event_id]),
                    metadata=alert["metadata"],
                )
                stored += 1
    newest = records[-1].get(time_field) if records else cursor
    return stored, newest, error


SOURCES = [("signins", "/auditLogs/signIns", "createdDateTime"), ("audits", "/auditLogs/directoryAudits", "activityDateTime"),
           ("alerts", "/security/alerts_v2", "createdDateTime")]


async def poll() -> Optional[Dict[str, Any]]:
    """Fetch what is new for the current organisation. None when another process is polling it, or it is not connected."""
    now = utcnow()
    connections = scoped(get_database(), "connections")
    connection = await connections.find_one_and_update(
        {**m365.KIND, "$or": [{"poll_lease_until": None}, {"poll_lease_until": {"$exists": False}}, {"poll_lease_until": {"$lte": now}}]},
        {"$set": {"poll_lease_until": now + POLL_LEASE}}, return_document=ReturnDocument.AFTER,
    )
    if not connection:
        return None
    counts: Dict[str, int] = {}
    cursors = dict(connection.get("cursors") or {})
    errors: Dict[str, str] = {}
    try:
        client = await m365.graph()
        if client is None:
            errors["signing_in"] = "Could not sign in to Microsoft 365: check the connection"
        else:
            async with client:
                for name, path, time_field in SOURCES:
                    try:
                        counts[name], cursors[name], error = await _poll_source(client, connection, name, path, time_field)
                    except httpx.HTTPError as e:
                        counts[name], error = 0, f"Could not reach Microsoft Graph: {e.__class__.__name__}"
                    if error:
                        errors[name] = error
    finally:
        await connections.update_one({"_id": connection["_id"]}, {"$set": {
            "cursors": cursors, "last_poll_at": utcnow(), "last_poll": counts, "errors": errors,
            "status": "error" if errors else "connected", "poll_lease_until": None,
        }})
    return {"counts": counts, "errors": errors}


async def poll_all() -> None:
    for tenant_id in await tenants.all_ids():
        with tenant_context(tenant_id):
            if await m365.get_connection():
                try:
                    await poll()
                except Exception:
                    logger.exception("Microsoft 365 poll failed")


async def poll_periodically() -> None:
    """Run for the life of the process: poll every M365_POLL_INTERVAL_SECONDS."""
    while True:
        try:
            await poll_all()
        except Exception as e:  # never let the loop die
            logger.error(f"Microsoft 365 polling failed: {e}")
        await asyncio.sleep(settings.M365_POLL_INTERVAL_SECONDS)


async def add_rules(user_id: Optional[str] = None) -> int:
    """Add the Microsoft 365 detection rules to the current organisation's catalogue (once each), and send them to the engine."""
    from core.services.detection_service import DetectionService
    from core.services.rule_sync import sync_rules

    rules = scoped(get_database(), "detection_rules")
    added = 0
    for rule in RULES:
        if await rules.find_one({"name": rule["name"]}, {"_id": 1}):
            continue
        await DetectionService().create_rule(
            DetectionRuleCreate(rule_type="signature", detection_source="identity", status="enabled", **rule), user_id
        )
        added += 1
    if added:
        await sync_rules()
    return added
