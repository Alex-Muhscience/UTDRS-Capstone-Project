"""
Response actions: what UTDRS can do about a threat, with a person's approval or on its own.

Each action acts on one entity (a user, an email message, a case) through a connector
(core.services.connectors). Every action is a record in `actions`: proposed, approved or
rejected, run, and undone, each step in the audit log and on its case's timeline.
Actions that can be undone save what undoing them needs when they run.

Safety (FR-RSP-08):
- An organisation's response mode caps what playbooks may do: "automatic", "approval"
  (the default: a person approves every action) or "notify" (actions are only
  suggested). A playbook can be more cautious than its organisation, never less.
- At most `max_actions_per_hour` actions run automatically per organisation in an hour;
  beyond that, they wait for approval.
- Protected accounts (listed by an administrator, plus the organisation's UTDRS
  administrators) are never disrupted automatically, and only an administrator can
  approve disrupting one.
- Disabling the last enabled Microsoft 365 Global Administrator is refused outright.
- Actions requested through an API key always wait for a person's approval.
"""
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from bson import ObjectId
from pymongo import ReturnDocument

from core.database.connection import get_database
from core.services import audit, case_service, connectors, tenants
from core.tenancy import current_tenant, scoped
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

MODES = ["automatic", "approval", "notify"]  # least to most cautious
DEFAULT_SETTINGS: Dict[str, Any] = {"mode": "approval", "max_actions_per_hour": 20, "protected_accounts": []}
GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"  # the role template's id, the same in every tenant


class ActionError(Exception):
    """An action could not be requested or run; the message says why, for people."""


class NotConnected(ActionError):
    pass


class Refused(ActionError):
    """A safety limit forbids this action."""


Handler = Callable[[Optional[httpx.AsyncClient], str, Dict[str, Any]], Awaitable[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]]


@dataclass(frozen=True)
class ActionType:
    name: str
    label: str
    description: str
    connector: str
    target: str  # the entity type it acts on
    handler: Handler
    params: Tuple[str, ...] = ()
    undo: Optional[str] = None  # the action that undoes it
    disruptive: bool = False  # stops someone working, so protected accounts need an administrator


# ---------------------------------------------------------------------------
# Microsoft 365, through Microsoft Graph

def _user(value: str) -> str:
    return f"/users/{quote(value, safe='@')}"


async def _graph(client: httpx.AsyncClient, method: str, path: str, **kwargs) -> Dict[str, Any]:
    response = await client.request(method, path, **kwargs)
    if response.is_error:
        try:
            message = response.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = response.text[:200]
        raise ActionError(f"Microsoft 365 refused it ({response.status_code}): {message}")
    return response.json() if response.content else {}


async def revoke_sessions(client, user, params):
    await _graph(client, "POST", f"{_user(user)}/revokeSignInSessions")
    return {"summary": "Signed out of every session; they must sign in again"}, None


async def _check_not_last_global_admin(client, user: str) -> None:
    members = await _graph(
        client, "GET", f"/directoryRoles(roleTemplateId='{GLOBAL_ADMINISTRATOR}')/members",
        params={"$select": "id,userPrincipalName,accountEnabled"},
    )
    admins = members.get("value", [])
    me = user.lower()
    if any(me in (str(a.get("id", "")).lower(), str(a.get("userPrincipalName", "")).lower()) for a in admins):
        others = [a for a in admins if me not in (str(a.get("id", "")).lower(), str(a.get("userPrincipalName", "")).lower()) and a.get("accountEnabled", True)]
        if not others:
            raise Refused("This is the last enabled Global Administrator; disabling it would lock everyone out")


async def disable_account(client, user, params):
    await _check_not_last_global_admin(client, user)
    await _graph(client, "PATCH", _user(user), json={"accountEnabled": False})
    return {"summary": "Account disabled; nobody can sign in to it"}, {}


async def enable_account(client, user, params):
    await _graph(client, "PATCH", _user(user), json={"accountEnabled": True})
    return {"summary": "Account enabled again"}, None


async def require_password_change(client, user, params):
    await _graph(client, "PATCH", _user(user), json={"passwordProfile": {"forceChangePasswordNextSignIn": True}})
    return {"summary": "They must choose a new password when they next sign in"}, None


RULE_READ_ONLY = ("id", "isReadOnly", "hasError", "@odata.context", "@odata.etag")


async def remove_inbox_rule(client, user, params):
    path = f"{_user(user)}/mailFolders/inbox/messageRules/{quote(str(params['rule_id']), safe='')}"
    rule = await _graph(client, "GET", path)
    await _graph(client, "DELETE", path)
    saved = {k: v for k, v in rule.items() if k not in RULE_READ_ONLY}
    return {"summary": f"Removed the inbox rule \"{rule.get('displayName', params['rule_id'])}\"", "rule": saved}, {"rule": saved}


async def restore_inbox_rule(client, user, params):
    rule = await _graph(client, "POST", f"{_user(user)}/mailFolders/inbox/messageRules", json=params["rule"])
    return {"summary": f"Put back the inbox rule \"{rule.get('displayName', '')}\"", "rule_id": rule.get("id")}, None


async def purge_message(client, message_id, params):
    """Move the message out of every recipient's mailbox, into their recoverable items."""
    moved, not_found = [], []
    escaped = message_id.replace("'", "''")
    for mailbox in dict.fromkeys(params["recipients"]):
        found = await _graph(
            client, "GET", f"{_user(mailbox)}/messages",
            params={"$filter": f"internetMessageId eq '{escaped}'", "$select": "id,parentFolderId"},
        )
        copies = found.get("value", [])
        if not copies:
            not_found.append(mailbox)
        for copy in copies:
            result = await _graph(client, "POST", f"{_user(mailbox)}/messages/{quote(copy['id'], safe='')}/move", json={"destinationId": "recoverableitemsdeletions"})
            moved.append({"mailbox": mailbox, "id": result.get("id", copy["id"]), "folder": copy.get("parentFolderId", "inbox")})
    summary = f"Removed from {len({m['mailbox'] for m in moved})} mailbox{'es' if len(moved) != 1 else ''}"
    if not_found:
        summary += f"; not found in {len(not_found)}"
    return {"summary": summary, "moved": len(moved), "not_found": not_found}, ({"moved": moved} if moved else None)


async def restore_message(client, message_id, params):
    for copy in params["moved"]:
        await _graph(client, "POST", f"{_user(copy['mailbox'])}/messages/{quote(copy['id'], safe='')}/move", json={"destinationId": copy["folder"]})
    return {"summary": f"Put back in {len(params['moved'])} mailbox{'es' if len(params['moved']) != 1 else ''}"}, None


# ---------------------------------------------------------------------------
# UTDRS itself

def _priority(params) -> str:
    if params["priority"] not in case_service.PRIORITIES:
        raise ActionError(f"Priority must be one of {', '.join(case_service.PRIORITIES)}")
    return params["priority"]


async def escalate_case(client, case_id, params):
    case = await case_service.get_case(case_id)
    if not case:
        raise ActionError("The case no longer exists")
    before, wanted = case["priority"], _priority(params)
    if case_service.PRIORITIES.index(before) >= case_service.PRIORITIES.index(wanted):
        return {"summary": f"Already {before} priority"}, None
    await case_service.update_case(case_id, {"priority": params["priority"]}, {"type": "response", "name": "Response action"})
    return {"summary": f"Priority raised from {before} to {params['priority']}"}, {"priority": before}


async def set_case_priority(client, case_id, params):
    _priority(params)
    await case_service.update_case(case_id, {"priority": params["priority"]}, {"type": "response", "name": "Response action"})
    return {"summary": f"Priority set back to {params['priority']}"}, None


CATALOGUE: Dict[str, ActionType] = {a.name: a for a in [
    ActionType("m365.revoke_sessions", "Sign out everywhere", "End all of the user's Microsoft 365 sessions, so whoever is using them must sign in again.",
               "m365", "user", revoke_sessions, disruptive=True),
    ActionType("m365.disable_account", "Disable the account", "Stop anyone signing in to the account until it is enabled again.",
               "m365", "user", disable_account, undo="m365.enable_account", disruptive=True),
    ActionType("m365.enable_account", "Enable the account", "Let the account sign in again.", "m365", "user", enable_account),
    ActionType("m365.require_password_change", "Require a new password", "Make the user choose a new password when they next sign in.",
               "m365", "user", require_password_change, disruptive=True),
    ActionType("m365.remove_inbox_rule", "Remove an inbox rule", "Delete an inbox rule, such as one forwarding mail to an outsider. The rule is kept so it can be put back.",
               "m365", "user", remove_inbox_rule, params=("rule_id",), undo="m365.restore_inbox_rule"),
    ActionType("m365.restore_inbox_rule", "Put back an inbox rule", "Recreate an inbox rule that was removed.", "m365", "user", restore_inbox_rule, params=("rule",)),
    ActionType("m365.purge_message", "Remove the email from every mailbox", "Move the message out of each recipient's mailbox into their recoverable items, where it can be put back.",
               "m365", "message", purge_message, params=("recipients",), undo="m365.restore_message"),
    ActionType("m365.restore_message", "Put the email back", "Return a removed message to the folders it was in.", "m365", "message", restore_message, params=("moved",)),
    ActionType("utdrs.escalate_case", "Raise the case's priority", "Raise the case's priority, so it is due sooner and stands out.",
               "utdrs", "case", escalate_case, params=("priority",), undo="utdrs.set_case_priority"),
    ActionType("utdrs.set_case_priority", "Set the case's priority", "Set the case's priority.", "utdrs", "case", set_case_priority, params=("priority",)),
]}
# Actions offered to people and playbooks; the rest exist only to undo others.
UNDO_ONLY = {a.undo for a in CATALOGUE.values() if a.undo} - {"m365.enable_account"}


def catalogue() -> List[Dict[str, Any]]:
    return [
        {"name": a.name, "label": a.label, "description": a.description, "connector": a.connector, "connector_name": connectors.NAMES.get(a.connector, a.connector),
         "target": a.target, "params": list(a.params), "can_undo": bool(a.undo), "disruptive": a.disruptive}
        for a in CATALOGUE.values() if a.name not in UNDO_ONLY
    ]


# ---------------------------------------------------------------------------
# Settings and safety

def _actions():
    return scoped(get_database(), "actions")


async def ensure_indexes() -> None:
    actions = get_database()["actions"]
    await actions.create_index([("tenant_id", 1), ("status", 1), ("created_at", -1)])
    await actions.create_index([("tenant_id", 1), ("case_id", 1), ("created_at", 1)])
    await actions.create_index([("tenant_id", 1), ("auto", 1), ("started_at", -1)])


async def get_settings() -> Dict[str, Any]:
    tenant = await tenants.get(current_tenant()) or {}
    return {**DEFAULT_SETTINGS, **(tenant.get("response") or {})}


async def update_settings(changes: Dict[str, Any]) -> Dict[str, Any]:
    current = await get_settings()
    if "protected_accounts" in changes:
        changes["protected_accounts"] = sorted({a.strip().lower() for a in changes["protected_accounts"] if a.strip()})
    updated = {**current, **changes}
    await get_database()["tenants"].update_one({"_id": ObjectId(current_tenant())}, {"$set": {"response": updated, "updated_at": utcnow()}})
    return updated


async def protected_accounts() -> set:
    listed = set((await get_settings())["protected_accounts"])
    admins = scoped(get_database(), "users").find({"role": "admin", "active": True}, {"email": 1, "username": 1})
    return listed | {str(value).lower() async for admin in admins for value in (admin.get("email"), admin.get("username")) if value}


def cautious(*modes: Optional[str]) -> str:
    return max((m for m in modes if m in MODES), key=MODES.index, default="approval")


# ---------------------------------------------------------------------------
# Requesting, approving, running and undoing actions

def present(doc: Dict[str, Any]) -> Dict[str, Any]:
    kind = CATALOGUE.get(doc["action"])
    out = {k: v for k, v in doc.items() if k not in ("tenant_id", "undo_params")}
    out["id"] = str(out.pop("_id"))
    out["label"] = kind.label if kind else doc["action"]
    out["can_undo"] = bool(kind and kind.undo and doc["status"] == "succeeded" and doc.get("undo_params") is not None)
    return out


def _validate(action: str, target: Dict[str, str], params: Dict[str, Any]) -> ActionType:
    kind = CATALOGUE.get(action)
    if not kind:
        raise ActionError(f"There is no action called {action}")
    if target.get("type") != kind.target or not str(target.get("value", "")).strip():
        raise ActionError(f"{kind.label} acts on a {kind.target}")
    missing = [p for p in kind.params if p not in params or params[p] in (None, "", [])]
    if missing:
        raise ActionError(f"{kind.label} needs {', '.join(missing)}")
    if kind.target == "case" and not ObjectId.is_valid(target["value"]):
        raise ActionError("That is not a case")
    return kind


async def request(
    action: str,
    target: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
    *,
    actor: Dict[str, Any],
    case_id: Optional[str] = None,
    alert_id: Optional[str] = None,
    playbook: Optional[Dict[str, Any]] = None,
    mode: str = "automatic",
    unattended: bool = False,
) -> Dict[str, Any]:
    """
    Propose an action. It runs now when `mode` (after the safety limits) is automatic;
    otherwise it waits for a person. `mode` is the requester's: "automatic" for a person
    acting themselves, a playbook's own mode for a playbook. `unattended` is for a
    playbook acting on its own, which the organisation's mode and hourly limit govern;
    a person running a playbook decides for themselves.
    """
    params = dict(params or {})
    kind = _validate(action, target, params)
    if not await connectors.connected(kind.connector):
        raise NotConnected(f"{connectors.NAMES.get(kind.connector, kind.connector)} is not connected")
    if kind.target == "case":
        if not await scoped(get_database(), "cases").find_one({"_id": ObjectId(target["value"])}, {"_id": 1}):
            raise ActionError("Case not found")
        case_id = target["value"]

    reasons: List[str] = []
    if actor.get("type") == "api_key":
        mode = cautious(mode, "approval")
        reasons.append("Requested through an API key")
    if unattended:
        settings = await get_settings()
        if cautious(mode, settings["mode"]) != mode:
            reasons.append(f"Your organisation's response mode is {settings['mode']}")
        mode = cautious(mode, settings["mode"])
        if mode == "automatic":
            since = utcnow() - timedelta(hours=1)
            if await _actions().count_documents({"auto": True, "started_at": {"$gte": since}}) >= settings["max_actions_per_hour"]:
                mode = "approval"
                reasons.append(f"More than {settings['max_actions_per_hour']} actions ran automatically in the last hour")
    protected = kind.disruptive and kind.target == "user" and target["value"].lower() in await protected_accounts()
    if protected and mode == "automatic" and (unattended or actor.get("role") != "admin"):
        mode = "approval"
        reasons.append("This is a protected account: an administrator must approve it")

    now = utcnow()
    doc: Dict[str, Any] = {
        "action": action,
        "target": {"type": target["type"], "value": str(target["value"]).strip()},
        "params": params,
        "status": "running" if mode == "automatic" else "pending",
        "mode": mode,
        "reason": "; ".join(reasons) or None,
        "protected": protected,
        "auto": unattended and mode == "automatic",
        "case_id": case_id,
        "alert_id": alert_id,
        "playbook": playbook,
        "requested_by": actor,
        "decided_by": actor if mode == "automatic" else None,
        "created_at": now,
        "started_at": now if mode == "automatic" else None,
        "finished_at": None,
        "result": None,
        "error": None,
    }
    doc["_id"] = (await _actions().insert_one(doc)).inserted_id
    if mode == "automatic":
        return await _run(doc)
    await _note(doc, f"{kind.label}: {'suggested' if mode == 'notify' else 'waiting for approval'}", actor)
    await audit.record("response.action_proposed", actor=actor, target=_audit_target(doc),
                       details={"action": action, "action_id": str(doc["_id"]), "mode": mode, "reason": doc["reason"]})
    return present(doc)


def _audit_target(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": doc["target"]["type"], "id": doc["target"]["value"]}


async def _note(doc: Dict[str, Any], text: str, actor: Optional[Dict[str, Any]]) -> None:
    if doc.get("case_id"):
        await case_service.add_entry(doc["case_id"], "action", actor, text, action_id=str(doc["_id"]), action=doc["action"], status=doc["status"])


async def _run(doc: Dict[str, Any]) -> Dict[str, Any]:
    kind = CATALOGUE[doc["action"]]
    client = await connectors.client(kind.connector) if kind.connector != "utdrs" else None
    status, result, undo_params, error = "succeeded", None, None, None
    try:
        if kind.connector != "utdrs" and client is None:
            raise NotConnected(f"{connectors.NAMES.get(kind.connector, kind.connector)} is not connected")
        result, undo_params = await kind.handler(client, doc["target"]["value"], doc["params"])
    except ActionError as e:
        status, error = "failed", str(e)
    except httpx.HTTPError as e:
        status, error = "failed", f"Could not reach {connectors.NAMES.get(kind.connector, kind.connector)}: {e.__class__.__name__}"
    except Exception as e:  # an unexpected failure is still recorded, never lost
        logger.exception(f"Action {doc['action']} failed")
        status, error = "failed", f"Unexpected error: {e.__class__.__name__}"
    finally:
        if client is not None:
            await client.aclose()
    updated = await _actions().find_one_and_update(
        {"_id": doc["_id"]},
        {"$set": {"status": status, "result": result, "undo_params": undo_params, "error": error, "finished_at": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    actor = doc.get("decided_by") or doc["requested_by"]
    await _note(updated, f"{kind.label}: {result['summary'] if result else 'failed — ' + error}", actor)
    await audit.record(
        f"response.action_{status}", actor=actor, target=_audit_target(updated), outcome="success" if status == "succeeded" else "failed",
        details={"action": doc["action"], "action_id": str(doc["_id"]), "case_id": doc.get("case_id"),
                 "playbook": (doc.get("playbook") or {}).get("name"), "result": result, "error": error},
    )
    return present(updated)


async def get(action_id: str) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(action_id):
        return None
    doc = await _actions().find_one({"_id": ObjectId(action_id)})
    return present(doc) if doc else None


async def list_actions(query: Dict[str, Any], limit: int, skip: int) -> List[Dict[str, Any]]:
    cursor = _actions().find(query).sort("created_at", -1).skip(skip).limit(limit)
    return [present(d) for d in await cursor.to_list(limit)]


async def approve(action_id: str, actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    doc = await _actions().find_one({"_id": ObjectId(action_id)}) if ObjectId.is_valid(action_id) else None
    if not doc:
        return None
    if doc["status"] != "pending":
        raise ActionError(f"This action is {doc['status']}, not waiting for approval")
    if doc.get("protected") and actor.get("role") != "admin":
        raise Refused("Only an administrator can approve an action on a protected account")
    claimed = await _actions().find_one_and_update(
        {"_id": doc["_id"], "status": "pending"},
        {"$set": {"status": "running", "decided_by": actor, "decided_at": utcnow(), "started_at": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    if not claimed:
        raise ActionError("Someone else decided on this action first")
    return await _run(claimed)


async def reject(action_id: str, actor: Dict[str, Any], reason: Optional[str]) -> Optional[Dict[str, Any]]:
    doc = await _actions().find_one({"_id": ObjectId(action_id)}) if ObjectId.is_valid(action_id) else None
    if not doc:
        return None
    updated = await _actions().find_one_and_update(
        {"_id": doc["_id"], "status": "pending"},
        {"$set": {"status": "rejected", "decided_by": actor, "decided_at": utcnow(), "error": reason}},
        return_document=ReturnDocument.AFTER,
    )
    if not updated:
        raise ActionError(f"This action is {doc['status']}, not waiting for approval")
    await _note(updated, f"{CATALOGUE[doc['action']].label}: not done{' — ' + reason if reason else ''}", actor)
    return present(updated)


async def undo(action_id: str, actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Undo an action that ran. The undo is an action of its own, linked both ways."""
    doc = await _actions().find_one({"_id": ObjectId(action_id)}) if ObjectId.is_valid(action_id) else None
    if not doc:
        return None
    kind = CATALOGUE[doc["action"]]
    if not kind.undo or doc["status"] != "succeeded" or doc.get("undo_params") is None:
        raise ActionError("This action cannot be undone" if not kind.undo else f"Only an action that ran can be undone; this one is {doc['status']}")
    # Claim it, so two people undoing at once undo it once.
    claimed = await _actions().update_one({"_id": doc["_id"], "status": "succeeded"}, {"$set": {"status": "undoing"}})
    if not claimed.modified_count:
        raise ActionError("Someone else is undoing this action")
    params = {**{p: doc["params"].get(p) for p in CATALOGUE[kind.undo].params if p in doc["params"]}, **doc["undo_params"]}
    try:
        reverse = await request(kind.undo, doc["target"], params, actor=actor, case_id=doc.get("case_id"))
    except ActionError:
        await _actions().update_one({"_id": doc["_id"]}, {"$set": {"status": "succeeded"}})
        raise
    succeeded = reverse["status"] == "succeeded"
    await _actions().update_one(
        {"_id": doc["_id"]},
        {"$set": {"status": "undone" if succeeded else "succeeded", **({"undone_by": reverse["id"], "undone_at": utcnow()} if succeeded else {})}},
    )
    await _actions().update_one({"_id": ObjectId(reverse["id"])}, {"$set": {"undoes": action_id}})
    return await get(reverse["id"])
