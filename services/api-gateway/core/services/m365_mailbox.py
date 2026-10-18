"""
Exchange's mailbox audit, from the Office 365 Management Activity API.

Attackers who get into a mailbox often add an inbox rule: forward mail to themselves,
or hide replies (delete them, or move them to a folder nobody looks at) while they
carry on a fraud from the account. Those changes are only in Exchange's audit log.

The Management Activity API works differently from Graph: UTDRS subscribes once to the
`Audit.Exchange` feed, then lists the content blobs created in a time window (at most a
day, within the last seven), and fetches each blob, a list of audit records. Only the
records that change inbox rules or mailbox forwarding become events (`mailbox`): the
rest of the mailbox audit is not kept (data minimisation). Each event says what the rule
does: the addresses it forwards or redirects to and whether any is outside the
organisation's verified domains, whether it hides mail, and the words it looks for.
"""
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from core.models.event import EventCreate
from utils.time import utcnow

CONTENT_TYPE = "Audit.Exchange"
OPERATIONS = {"New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox"}
RULE_OPERATIONS = {"New-InboxRule", "Set-InboxRule", "UpdateInboxRules"}
FORWARD_PARAMETERS = ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "ForwardingSmtpAddress", "ForwardingAddress")
HIDING_FOLDERS = {"rss subscriptions", "rss feeds", "conversation history", "archive", "junk email", "deleted items"}
MAX_WINDOW = timedelta(hours=24)
MAX_AGE = timedelta(days=7) - timedelta(hours=1)
MAX_PAGES = 20
ADDRESS = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _parameters(record: Dict[str, Any]) -> Dict[str, str]:
    values = {p.get("Name"): str(p.get("Value") or "") for p in record.get("Parameters") or []}
    values.update({p.get("Name"): str(p.get("Value") or "") for p in record.get("OperationProperties") or []})
    return values


def _client_ip(value: Optional[str]) -> Optional[str]:
    """Exchange writes addresses with ports ("203.0.113.5:51234", "[2001:db8::1]:443")."""
    if not value:
        return None
    if value.startswith("["):
        return value[1:value.index("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def mailbox_event(record: Dict[str, Any], domains: Set[str]) -> Optional[EventCreate]:
    """An event for a record that changes an inbox rule or forwarding; None for other records."""
    operation = record.get("Operation")
    if operation not in OPERATIONS:
        return None
    params = _parameters(record)
    user = (record.get("UserId") or "").lower()
    own = {user.rsplit("@", 1)[-1]} if "@" in user else set()
    known = {d.lower() for d in domains} | own

    targets = sorted({a.lower() for name in FORWARD_PARAMETERS for a in ADDRESS.findall(params.get(name, ""))})
    actions = params.get("RuleActions", "")  # from Outlook (UpdateInboxRules): a JSON list of actions
    targets += [a.lower() for a in ADDRESS.findall(actions) if a.lower() not in targets]
    external = [a for a in targets if a.rsplit("@", 1)[-1] not in known]

    folder = params.get("MoveToFolder", "")
    hides = (
        params.get("DeleteMessage", "").lower() == "true"
        or params.get("SoftDeleteMessage", "").lower() == "true"
        or folder.strip().lower() in HIDING_FOLDERS
        or any(word in actions for word in ('"Delete"', "PermanentDelete"))
    )
    rule_name = params.get("Name") or params.get("RuleName") or (record.get("ObjectId") or "").rsplit("\\", 1)[-1] or None
    if operation == "Set-Mailbox" and not targets:
        return None  # a mailbox setting other than forwarding
    words = [w.strip() for w in re.split(r"[;,]", params.get("SubjectOrBodyContainsWords", "") + ";" + params.get("SubjectContainsWords", "")) if w.strip()]
    what = "set forwarding" if operation == "Set-Mailbox" else f"{'created' if operation.startswith('New') else 'changed'} the inbox rule \"{rule_name}\""
    detail = []
    if targets:
        detail.append(f"forwards to {', '.join(targets[:3])}")
    if hides:
        detail.append(f"hides mail{' in ' + folder if folder else ''}")
    return EventCreate(
        timestamp=datetime.fromisoformat((record.get("CreationTime") or utcnow().isoformat()).replace("Z", "+00:00")),
        event_type="mailbox",
        source="m365",
        source_ip=_client_ip(record.get("ClientIP")),
        user_id=user or None,
        action=operation,
        description=f"{user or 'Someone'} {what}" + (f": {'; '.join(detail)}" if detail else ""),
        raw_data={
            "external_id": f"exchange:{record['Id']}",
            "activity": operation,
            "user": user or None,
            "source_ip": _client_ip(record.get("ClientIP")),
            "rule_name": rule_name if operation in RULE_OPERATIONS else None,
            "forward_to": targets,
            "external_forward": bool(external),
            "external_addresses": external,
            "hides_mail": hides,
            "move_to_folder": folder or None,
            "keywords": words[:20],
            "result": record.get("ResultStatus"),
        },
    )


def _window(cursor: Optional[str], now: datetime) -> Tuple[datetime, datetime]:
    """The next window to list: from the cursor, at most a day long, within the last seven days."""
    start = datetime.fromisoformat(cursor) if cursor else now - timedelta(days=1)
    start = max(start, now - MAX_AGE)
    return start, min(start + MAX_WINDOW, now)


def _api_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S")


async def subscribe(client: httpx.AsyncClient) -> Optional[str]:
    """Start the Audit.Exchange subscription (starting one that exists is fine). Returns an error, or None."""
    response = await client.post("/subscriptions/start", params={"contentType": CONTENT_TYPE})
    if response.is_success or "AF20024" in response.text:  # already enabled
        return None
    if response.status_code in (401, 403):
        return "Not allowed: needs ActivityFeed.Read (Office 365 Management APIs)"
    return f"Could not subscribe to the mailbox audit ({response.status_code}): {response.text[:200]}"


async def fetch(client: httpx.AsyncClient, cursor: Optional[str]) -> Tuple[List[Dict[str, Any]], str, Optional[str]]:
    """
    The audit records in content created since `cursor`, the new cursor, and any error.
    Only the window's blobs are read; a poll a long way behind catches up a day at a time.
    """
    start, end = _window(cursor, utcnow())
    records: List[Dict[str, Any]] = []
    url: Optional[str] = "/subscriptions/content"
    params: Optional[Dict[str, str]] = {"contentType": CONTENT_TYPE, "startTime": _api_time(start), "endTime": _api_time(end)}
    for _ in range(MAX_PAGES):
        response = await client.get(url, params=params)
        if response.status_code in (401, 403):
            return records, cursor or start.isoformat(), "Not allowed: needs ActivityFeed.Read (Office 365 Management APIs)"
        if response.is_error:
            return records, cursor or start.isoformat(), f"The Office 365 Management API answered {response.status_code}"
        for blob in response.json() or []:
            content = await client.get(blob["contentUri"])
            if content.is_error:
                return records, cursor or start.isoformat(), f"Could not read audit content ({content.status_code})"
            records += [r for r in content.json() or [] if r.get("Operation") in OPERATIONS]
        url, params = response.headers.get("NextPageUri"), None
        if not url:
            break
    if url:
        # More pages than one poll reads: read this window again next time (records are
        # stored once), rather than skip what was not reached.
        return records, cursor or start.isoformat(), None
    return records, end.isoformat(), None
