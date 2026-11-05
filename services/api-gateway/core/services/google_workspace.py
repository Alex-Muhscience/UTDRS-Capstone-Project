"""
The Google Workspace connector: sign-ins, administrator actions and app authorisations
from an organisation's Google Workspace, and response actions on its accounts.

An organisation connects with a service account it creates in Google Cloud, given
domain-wide delegation in the Google Admin console for SCOPES, and acting as one of its
Workspace administrators (`admin_email`). Its JSON key is stored encrypted (utils/crypto.py,
bound to the organisation). UTDRS signs a JWT with the key and exchanges it for an access
token (OAuth 2.0 for service accounts), cached until shortly before it expires.

Every GOOGLE_POLL_INTERVAL_SECONDS the Admin SDK Reports API is read for: `login` (sign-ins,
failures, suspicious sign-ins, 2-step verification), `admin` (roles and privileges granted,
accounts changed), `token` (apps authorised), `user_accounts` (account settings, such as
mail forwarded outside the domain) and `drive`, for sharing changes only (who a file is
shared with, and its link sharing; only primary events).
Google publishes these with some delay, so each poll reads from a little before the last
activity it saw; each activity is stored once (raw_data.external_id). Sign-ins become
`authentication` events, so the engine's identity correlations (password spraying and
guessing, success after failures) apply to them as to Microsoft 365's.
"""
import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
import jwt
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from config import settings
from core.database.connection import get_database
from core.models.event import EventCreate
from core.services import connectors, heartbeat, tenants
from core.tenancy import current_tenant, scoped, tenant_context
from utils import crypto
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

KIND = {"connector": "google"}
SOURCE = "google"
SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user",
]
REPORTS = "https://admin.googleapis.com/admin/reports/v1"
DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
APPLICATIONS = ("login", "admin", "token", "user_accounts", "drive")
# Only these Drive events are read: sharing changes. Views and edits are far too many to poll.
DRIVE_EVENTS = ("change_user_access", "change_document_visibility", "change_document_access_scope")
TOKEN_MARGIN_SECONDS = 120
TIMEOUT = httpx.Timeout(20.0, connect=10.0)
FIRST_LOOK_BACK = timedelta(days=1)
# Google can take a while to publish activities: each poll looks back this far before the last one seen.
OVERLAP = timedelta(hours=1)
MAX_PAGES = 20
POLL_LEASE = timedelta(minutes=10)

# Tests replace this to answer for Google.
transport: Optional[httpx.AsyncBaseTransport] = None
_tokens: Dict[str, Tuple[str, float]] = {}


class GoogleError(ValueError):
    """The connection cannot be made or used; the message says why, for people."""


def _connections():
    return scoped(get_database(), "connections")


def _context() -> str:
    return f"google:{current_tenant()}"


async def get_connection() -> Optional[Dict[str, Any]]:
    return await _connections().find_one(KIND)


# ---------------------------------------------------------------------------- Signing in

def parse_key(text: str) -> Dict[str, str]:
    """The parts of a service account's JSON key UTDRS needs; refuses anything else."""
    try:
        key = json.loads(text)
    except ValueError:
        raise GoogleError("That is not a service account key: paste the JSON file Google Cloud gave you")
    if not isinstance(key, dict) or key.get("type") != "service_account":
        raise GoogleError("That is not a service account key (its type should be service_account)")
    missing = [f for f in ("client_email", "private_key", "client_id") if not key.get(f)]
    if missing:
        raise GoogleError(f"The key has no {', '.join(missing)}")
    token_uri = key.get("token_uri") or "https://oauth2.googleapis.com/token"
    if not token_uri.startswith("https://oauth2.googleapis.com/"):
        raise GoogleError("The key's token_uri is not Google's")
    return {"client_email": key["client_email"], "private_key": key["private_key"], "client_id": str(key["client_id"]), "token_uri": token_uri}


async def _sign_in(key: Dict[str, str], admin_email: str) -> Tuple[str, int]:
    now = int(time.time())
    assertion = jwt.encode(
        {"iss": key["client_email"], "sub": admin_email, "scope": " ".join(SCOPES), "aud": key["token_uri"], "iat": now, "exp": now + 3600},
        key["private_key"], algorithm="RS256",
    )
    async with httpx.AsyncClient(timeout=TIMEOUT, transport=transport) as client:
        response = await client.post(key["token_uri"], data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
    if response.is_error:
        try:
            body = response.json()
            reason = body.get("error_description") or body.get("error") or response.text[:200]
        except ValueError:
            reason = response.text[:200]
        if "unauthorized_client" in response.text:
            reason = "the service account is not allowed to act for your domain: give it domain-wide delegation for UTDRS's scopes in the Google Admin console"
        raise GoogleError(f"Google refused to sign in ({response.status_code}): {reason}")
    body = response.json()
    return body["access_token"], int(body.get("expires_in", 3600))


async def token(connection: Optional[Dict[str, Any]] = None) -> str:
    connection = connection or await get_connection()
    if not connection:
        raise GoogleError("Google Workspace is not connected")
    tenant = current_tenant()
    cached = _tokens.get(tenant)
    if cached and cached[1] > time.time() + TOKEN_MARGIN_SECONDS:
        return cached[0]
    key = json.loads(crypto.decrypt(connection["key"], _context()))
    access, lifetime = await _sign_in(key, connection["admin_email"])
    _tokens[tenant] = (access, time.time() + lifetime)
    return access


async def client() -> Optional[httpx.AsyncClient]:
    """An authenticated client for the current organisation's Google Workspace, or None when it is not connected."""
    connection = await get_connection()
    if not connection:
        return None
    try:
        access = await token(connection)
    except (GoogleError, crypto.DecryptionFailed) as e:
        logger.warning(f"Could not sign in to Google Workspace: {e}")
        return None
    return httpx.AsyncClient(base_url=DIRECTORY, headers={"Authorization": f"Bearer {access}"}, timeout=TIMEOUT, transport=transport)


connectors.register("google", client)
connectors.NAMES["google"] = "Google Workspace"


# ---------------------------------------------------------------------------- Connecting

async def connect(key_json: str, admin_email: str, actor: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the service account key (encrypted) and check it can sign in as `admin_email`."""
    if not crypto.available():
        raise GoogleError("Connecting Google Workspace needs ENCRYPTION_KEY set on the gateway, to keep the key")
    key = parse_key(key_json)
    admin_email = admin_email.strip().lower()
    if "@" not in admin_email:
        raise GoogleError("Give the email address of a Google Workspace administrator for UTDRS to act as")
    await _sign_in(key, admin_email)  # refuse a key that does not work, before keeping it
    _tokens.pop(current_tenant(), None)
    now = utcnow()
    await _connections().update_one(KIND, {
        "$set": {**KIND, "status": "connected", "client_email": key["client_email"], "client_id": key["client_id"], "admin_email": admin_email,
                 "domain": admin_email.rsplit("@", 1)[1], "key": crypto.encrypt(json.dumps(key), _context()), "connected_at": now,
                 "connected_by": actor, "errors": {}, "error_since": None},
        "$setOnInsert": {"cursors": {}, "last_poll_at": None, "last_poll": {}},
    }, upsert=True)
    return await get_connection()


async def disconnect() -> bool:
    _tokens.pop(current_tenant(), None)
    return bool((await _connections().delete_one(KIND)).deleted_count)


def public(connection: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not connection:
        return {"connected": False, "encryption_available": crypto.available(), "scopes": SCOPES}
    return {
        "connected": True, "status": connection.get("status"), "client_email": connection.get("client_email"),
        "client_id": connection.get("client_id"), "admin_email": connection.get("admin_email"), "domain": connection.get("domain"),
        "connected_at": connection.get("connected_at"), "last_poll_at": connection.get("last_poll_at"), "last_poll": connection.get("last_poll") or {},
        "last_data_at": connection.get("last_data_at"), "error_since": connection.get("error_since"), "errors": connection.get("errors") or {},
        "encryption_available": crypto.available(), "scopes": SCOPES,
    }


# ---------------------------------------------------------------------------- Activities as events

def _parameters(event: Dict[str, Any]) -> Dict[str, Any]:
    found = {}
    for parameter in event.get("parameters") or []:
        for kind in ("value", "boolValue", "intValue", "multiValue"):
            if kind in parameter:
                found[parameter["name"]] = parameter[kind]
                break
    return found


def _time(value: Optional[str]) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return utcnow()


SIGN_IN_OUTCOME = {"login_success": "success", "login_failure": "failure"}


def activity_events(application: str, activity: Dict[str, Any]) -> List[EventCreate]:
    """One event for each event in a Reports activity."""
    ident = activity.get("id") or {}
    actor = (activity.get("actor") or {}).get("email") or ""
    address = activity.get("ipAddress")
    region = (activity.get("networkInfo") or {}).get("regionCode")
    events = []
    for index, item in enumerate(activity.get("events") or []):
        name = item.get("name") or "unknown"
        params = _parameters(item)
        external_id = f"google:{application}:{ident.get('uniqueQualifier')}:{ident.get('time')}:{index}"
        data: Dict[str, Any] = {"external_id": external_id, "activity": name, "category": item.get("type"), "user": actor.lower() or None,
                                "source_ip": address, "country": region, **{k.lower(): v for k, v in params.items()}}
        if application == "login":
            outcome = SIGN_IN_OUTCOME.get(name)
            if outcome:
                data["status"] = outcome
            description = f"Google sign-in by {actor or 'unknown user'}: {name.replace('_', ' ')}"
            if params.get("login_failure_type"):
                description += f" ({params['login_failure_type']})"
            event_type = "authentication"
        elif application == "drive":
            if params.get("primary_event") is False:
                continue  # one action can make several events; only its primary one is kept
            title = params.get("doc_title") or "a file"
            data["target_user"] = (params.get("target_user") or "").lower() or None
            if name == "change_document_visibility":
                description = f"{actor or 'Someone'} changed who can open {title} with its link to {params.get('new_value') or 'something else'}"
            elif name == "change_document_access_scope":
                description = f"{actor or 'Someone'} changed what people with the link to {title} can do to {params.get('new_value') or 'something else'}"
            else:
                description = f"{actor or 'Someone'} changed {params.get('target_user') or 'someone'}'s access to {title}"
            if params.get("visibility_change") == "external":
                description += ", sharing it outside your organisation"
            event_type = "file_sharing"
        elif application == "user_accounts":
            description = f"{actor or 'Someone'}: {name.replace('_', ' ')} (Google account settings)"
            event_type = "audit"
        elif application == "token":
            scopes = params.get("scope") or []
            data["scopes"] = " ".join(scopes) if isinstance(scopes, list) else str(scopes)
            description = f"{actor or 'Someone'} {name.replace('_', ' ')}d {params.get('app_name') or 'an app'} in Google Workspace"
            event_type = "audit"
        else:
            data["target_user"] = (params.get("USER_EMAIL") or "").lower() or None
            data["role"] = params.get("ROLE_NAME")
            description = f"Google Workspace administrator action by {actor or 'unknown'}: {name.replace('_', ' ').lower()}"
            event_type = "audit"
        events.append(EventCreate(
            timestamp=_time(ident.get("time")), event_type=event_type, source=SOURCE, source_ip=address, user_id=actor.lower() or None,
            action=data.get("status") or name, description=description[:500], raw_data=data,
        ))
    return events


# ---------------------------------------------------------------------------- Polling

async def _fetch(http: httpx.AsyncClient, application: str, since: datetime) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if application == "drive":
        found: List[Dict[str, Any]] = []
        for event_name in DRIVE_EVENTS:
            activities, error = await _fetch_one(http, application, since, event_name)
            found += activities
            if error:
                return found, error
        return found, None
    return await _fetch_one(http, application, since)


async def _fetch_one(http: httpx.AsyncClient, application: str, since: datetime, event_name: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    url = f"{REPORTS}/activity/users/all/applications/{application}"
    params: Dict[str, str] = {"startTime": since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "maxResults": "1000"}
    if event_name:
        params["eventName"] = event_name
    activities: List[Dict[str, Any]] = []
    for _ in range(MAX_PAGES):
        response = await http.get(url, params=params)
        if response.status_code == 429:
            return activities, "Google is limiting requests; trying again at the next poll"
        if response.status_code == 403:
            return activities, "Not allowed: the service account's delegation needs the admin.reports.audit.readonly scope"
        if response.is_error:
            return activities, f"Google answered {response.status_code}"
        body = response.json()
        activities += body.get("items") or []
        if not body.get("nextPageToken"):
            break
        params["pageToken"] = body["nextPageToken"]
    return activities, None


async def _store(event: EventCreate) -> bool:
    from core.services.detection_pipeline import analyse_event
    from core.services.event_service import EventService

    try:
        event_id = await EventService().create_event(event)
    except DuplicateKeyError:
        return False  # already have it (the polls overlap)
    await analyse_event(event_id, event)
    return True


async def poll() -> Optional[Dict[str, Any]]:
    """Fetch what is new for the current organisation. None when another process is polling it, or it is not connected."""
    now = utcnow()
    connection = await _connections().find_one_and_update(
        {**KIND, "$or": [{"poll_lease_until": None}, {"poll_lease_until": {"$exists": False}}, {"poll_lease_until": {"$lte": now}}]},
        {"$set": {"poll_lease_until": now + POLL_LEASE}}, return_document=ReturnDocument.AFTER,
    )
    if not connection:
        return None
    counts: Dict[str, int] = {}
    cursors = dict(connection.get("cursors") or {})
    errors: Dict[str, str] = {}
    try:
        try:
            access = await token(connection)
        except (GoogleError, crypto.DecryptionFailed) as e:
            errors["signing_in"] = str(e)
        else:
            async with httpx.AsyncClient(headers={"Authorization": f"Bearer {access}"}, timeout=TIMEOUT, transport=transport) as http:
                for application in APPLICATIONS:
                    last = cursors.get(application)
                    since = (_time(last) - OVERLAP) if last else now - FIRST_LOOK_BACK
                    try:
                        activities, error = await _fetch(http, application, since)
                    except httpx.HTTPError as e:
                        activities, error = [], f"Could not reach Google: {e.__class__.__name__}"
                    stored = 0
                    for activity in sorted(activities, key=lambda a: (a.get("id") or {}).get("time") or ""):
                        for event in activity_events(application, activity):
                            stored += await _store(event)
                        seen = (activity.get("id") or {}).get("time")
                        if seen and (not cursors.get(application) or seen > cursors[application]):
                            cursors[application] = seen
                    counts[application] = stored
                    if error:
                        errors[application] = error
    finally:
        done = utcnow()
        health: Dict[str, Any] = {"error_since": (connection.get("error_since") or done) if errors else None}
        if any(counts.values()):
            health["last_data_at"] = done
        await _connections().update_one({"_id": connection["_id"]}, {"$set": {
            "cursors": cursors, "last_poll_at": done, "last_poll": counts, "errors": errors,
            "status": "error" if errors else "connected", "poll_lease_until": None, **health,
        }})
    return {"counts": counts, "errors": errors}


async def poll_all() -> None:
    for tenant_id in await tenants.all_ids():
        with tenant_context(tenant_id):
            if await get_connection():
                try:
                    await add_rules()
                    await poll()
                except Exception:
                    logger.exception("Google Workspace poll failed")


async def poll_periodically() -> None:
    while True:
        error = None
        try:
            await poll_all()
        except Exception as e:  # never let the loop die
            logger.error(f"Google Workspace polling failed: {e}")
            error = e
        await heartbeat.beat("google_polling", settings.GOOGLE_POLL_INTERVAL_SECONDS, error)
        await asyncio.sleep(settings.GOOGLE_POLL_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------- Detection rules

RULES: List[Dict[str, Any]] = [
    {
        "name": "Google Workspace: suspicious sign-in",
        "description": "Google flagged a sign-in as suspicious (an unusual place or device): the account may be in someone else's hands.",
        "severity": "high",
        "tags": ["identity", "account-compromise", "T1078"],
        "logic": "source == 'google' and event_type == 'authentication' and activity in "
                 "['suspicious_login', 'suspicious_login_less_secure_app', 'suspicious_programmatic_login']",
    },
    {
        "name": "Google Workspace: government-backed attack warning",
        "description": "Google warned that government-backed attackers may be trying to take over this account.",
        "severity": "critical",
        "tags": ["identity", "account-compromise", "T1078"],
        "logic": "source == 'google' and event_type == 'authentication' and activity == 'gov_attack_warning'",
    },
    {
        "name": "Google Workspace: account disabled as hijacked",
        "description": "Google disabled an account because it was hijacked or its password leaked.",
        "severity": "high",
        "tags": ["identity", "account-compromise", "T1078"],
        "logic": "source == 'google' and event_type == 'authentication' and activity in "
                 "['account_disabled_hijacked', 'account_disabled_password_leak', 'account_disabled_spamming_through_relay', 'account_disabled_spamming']",
    },
    {
        "name": "Google Workspace: 2-step verification turned off",
        "description": "2-step verification was turned off for an account, which makes it easier to take over.",
        "severity": "medium",
        "tags": ["identity", "mfa", "T1556.006"],
        "logic": "source == 'google' and event_type == 'authentication' and activity == '2sv_disable'",
    },
    {
        "name": "Google Workspace: administrator privileges granted",
        "description": "Someone was given administrator privileges. Check it was intended: attackers give themselves admin rights to stay in.",
        "severity": "high",
        "tags": ["identity", "privilege-escalation", "T1098.003"],
        "logic": "source == 'google' and event_type == 'audit' and activity in ['ASSIGN_ROLE', 'GRANT_ADMIN_PRIVILEGE', 'GRANT_DELEGATED_ADMIN_PRIVILEGES']",
    },
    {
        "name": "Google Workspace: file shared outside",
        "description": "A Drive file was shared with people outside your organisation. Check it was meant to be: it is how data leaves.",
        "severity": "medium",
        "tags": ["data", "exfiltration", "T1567"],
        "logic": "source == 'google' and event_type == 'file_sharing' and visibility_change == 'external'",
    },
    {
        "name": "Google Workspace: many files shared outside",
        "description": "One person shared more than 20 files outside your organisation within an hour: data may be leaving in bulk.",
        "severity": "high",
        "tags": ["data", "exfiltration", "T1567"],
        "logic": "source == 'google' and event_type == 'file_sharing' and visibility_change == 'external' | count by user > 20 in 1h",
    },
    {
        "name": "Google Workspace: file made public on the web",
        "description": "A Drive file was made public on the web: anyone can find and open it, without signing in.",
        "severity": "high",
        "tags": ["data", "exfiltration", "T1567"],
        "logic": "source == 'google' and event_type == 'file_sharing' and activity == 'change_document_visibility' and new_value == 'public_on_the_web'",
    },
    {
        "name": "Google Workspace: mail forwarded outside",
        "description": "An account was set to forward its mail outside your organisation: a common way to keep reading a taken-over mailbox.",
        "severity": "high",
        "tags": ["email", "inbox-rule", "T1114.003"],
        "logic": "source == 'google' and event_type == 'audit' and activity == 'email_forwarding_out_of_domain'",
    },
    {
        "name": "Google Workspace: app given access to mail or files",
        "description": "Someone let an app read their Gmail or Drive. Consent phishing tricks people into granting this to an attacker's app.",
        "severity": "medium",
        "tags": ["identity", "oauth-consent", "T1528"],
        "logic": "source == 'google' and event_type == 'audit' and activity == 'authorize' and scopes matches "
                 "'(?i)(mail\\.google\\.com|auth/gmail|auth/drive)'",
    },
]


async def add_rules(user_id: Optional[str] = None) -> int:
    """Add the Google Workspace detection rules to the current organisation's catalogue (once each), and send them to the engine."""
    from core.models.detection import DetectionRuleCreate
    from core.services.detection_service import DetectionService
    from core.services.rule_sync import sync_rules

    rules = scoped(get_database(), "detection_rules")
    added = 0
    for rule in RULES:
        if await rules.find_one({"name": rule["name"]}, {"_id": 1}):
            continue
        await DetectionService().create_rule(DetectionRuleCreate(rule_type="signature", detection_source="identity", status="enabled", **rule), user_id)
        added += 1
    if added:
        await sync_rules()
    return added


_first_polls: set = set()


def start_first_poll() -> None:
    """Fetch the last day now, in the background, so a newly connected organisation sees results in minutes."""
    task = asyncio.create_task(poll())  # copies the current organisation with the context
    _first_polls.add(task)
    task.add_done_callback(_first_polls.discard)


async def idle() -> None:
    """Wait for first polls in progress (for tests and shutdown)."""
    from core.services.playbooks import wait_for_tasks

    await wait_for_tasks(_first_polls)
