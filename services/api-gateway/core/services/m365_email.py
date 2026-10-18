"""
Checking an email for phishing: fetched from the recipient's mailbox through Graph.

A message is checked when an analyst asks (by recipient and Internet message id), and for
every message a Microsoft Defender alert names. UTDRS reads its headers, sender, links
and attachments, and becomes an `email` event with what they show: whether SPF, DKIM and
DMARC passed, whether the Reply-To goes elsewhere, whether the sender is outside the
organisation, the link domains, and the attachments' names, types and SHA-256 hashes.

The body is sent to the core engine for its phishing model, and not kept: the event
stores none of the message's text beyond its subject (data minimisation), and
attachments are hashed and dropped. The engine's verdict, and the email rules in the
catalogue, raise alerts like any other, so the phishing playbook can remove the message
from every mailbox.
"""
import base64
import hashlib
import html
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

from core.models.event import EventCreate
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_BODY_CHARS = 50000
MAX_LINKS = 50
URL = re.compile(r"""https?://[^\s"'<>()]+""", re.IGNORECASE)
HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
TAGS = re.compile(r"<[^>]+>")
RISKY_EXTENSIONS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "lnk", "iso", "img", "vhd",
    "msi", "jar", "docm", "xlsm", "pptm", "one", "html", "htm", "svg",
}
SELECT = "id,subject,from,sender,replyTo,toRecipients,receivedDateTime,internetMessageId,internetMessageHeaders,body,hasAttachments"


class MessageNotFound(LookupError):
    pass


def _address(field: Optional[Dict[str, Any]]) -> Optional[str]:
    return ((field or {}).get("emailAddress") or {}).get("address", "").lower() or None


def _domain(address: Optional[str]) -> Optional[str]:
    return address.rsplit("@", 1)[-1].lower() if address and "@" in address else None


def authentication_results(headers: List[Dict[str, str]]) -> Dict[str, Optional[str]]:
    """SPF, DKIM and DMARC as the receiving server recorded them (Authentication-Results)."""
    text = " ".join(h.get("value", "") for h in headers if h.get("name", "").lower() == "authentication-results").lower()
    found = {}
    for check in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{check}=(\w+)", text)
        found[check] = match.group(1) if match else None
    return found


def links_in(body: str) -> List[str]:
    found = HREF.findall(body) + URL.findall(html.unescape(TAGS.sub(" ", body)))
    links = [html.unescape(link).rstrip(".,;") for link in found if link.lower().startswith(("http://", "https://"))]
    return list(dict.fromkeys(links))[:MAX_LINKS]


def text_of(body: Dict[str, Any]) -> str:
    content = body.get("content") or ""
    if (body.get("contentType") or "").lower() == "html":
        content = html.unescape(TAGS.sub(" ", re.sub(r"(?is)<(script|style).*?</\1>", " ", content)))
    return re.sub(r"\s+", " ", content).strip()[:MAX_BODY_CHARS]


async def _find(client: httpx.AsyncClient, mailbox: str, message_id: str) -> Dict[str, Any]:
    escaped = message_id.replace("'", "''")
    response = await client.get(
        f"/users/{quote(mailbox, safe='@')}/messages",
        params={"$filter": f"internetMessageId eq '{escaped}'", "$select": SELECT},
    )
    if response.status_code in (401, 403):
        raise PermissionError("Not allowed to read this mailbox: needs Mail.ReadWrite")
    if response.status_code == 404:
        raise MessageNotFound(f"{mailbox} is not a mailbox in your organisation")
    response.raise_for_status()
    found = response.json().get("value") or []
    if not found:
        raise MessageNotFound(f"No message {message_id} in {mailbox}'s mailbox")
    return found[0]


async def _attachments(client: httpx.AsyncClient, mailbox: str, message: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not message.get("hasAttachments"):
        return []
    response = await client.get(f"/users/{quote(mailbox, safe='@')}/messages/{quote(message['id'], safe='')}/attachments")
    if response.is_error:
        return []
    out = []
    for attachment in response.json().get("value") or []:
        name = attachment.get("name") or ""
        item = {"name": name, "type": attachment.get("contentType"), "size": attachment.get("size"), "sha256": None,
                "risky": name.rsplit(".", 1)[-1].lower() in RISKY_EXTENSIONS if "." in name else False}
        content = attachment.get("contentBytes")
        if content and (attachment.get("size") or 0) <= MAX_ATTACHMENT_BYTES:
            item["sha256"] = hashlib.sha256(base64.b64decode(content)).hexdigest()  # the bytes are not kept
        out.append(item)
    return out


async def read_message(client: httpx.AsyncClient, mailbox: str, message_id: str, domains: set) -> Dict[str, Any]:
    """The message as UTDRS judges it: an event to keep, and the body for the engine only."""
    message = await _find(client, mailbox, message_id)
    attachments = await _attachments(client, mailbox, message)
    sender = _address(message.get("from")) or _address(message.get("sender"))
    reply_to = [_address(r) for r in message.get("replyTo") or [] if _address(r)]
    auth = authentication_results(message.get("internetMessageHeaders") or [])
    body = message.get("body") or {}
    links = links_in(body.get("content") or "")
    own = {d.lower() for d in domains} | ({_domain(mailbox)} if _domain(mailbox) else set())
    received = message.get("receivedDateTime")
    event = EventCreate(
        timestamp=datetime.fromisoformat(received.replace("Z", "+00:00")) if received else utcnow(),
        event_type="email",
        source="m365",
        user_id=mailbox.lower(),
        description=f"Email to {mailbox.lower()} from {sender or 'an unknown sender'}: {message.get('subject') or '(no subject)'}",
        raw_data={
            "external_id": f"email:{mailbox.lower()}:{message.get('internetMessageId') or message_id}",
            "internet_message_id": message.get("internetMessageId") or message_id,
            "recipient": mailbox.lower(),
            "user": mailbox.lower(),
            "sender": sender,
            "sender_domain": _domain(sender),
            "external_sender": _domain(sender) not in own if sender else None,
            "reply_to": reply_to,
            "reply_to_mismatch": any(_domain(r) != _domain(sender) for r in reply_to) if sender else False,
            "subject": message.get("subject"),
            **auth,
            "links": links,
            "link_domains": sorted({urlparse(link).hostname or "" for link in links} - {""}),
            "attachments": attachments,
            "risky_attachment": any(a["risky"] for a in attachments),
            "sha256": next((a["sha256"] for a in attachments if a["sha256"]), None),
        },
    )
    return {"event": event, "body": text_of(body)}


async def analyse(mailbox: str, message_id: str, reported_by: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Check one message for the current organisation: stored as an event (once per mailbox
    and message) and judged by the engine. Returns the event id, the alert id if one was
    raised, and whether it had been checked before.
    """
    from core.services import m365
    from core.services.detection_pipeline import analyse_event
    from core.services.event_service import EventService
    from core.services.m365_ingest import _verified_domains
    from pymongo.errors import DuplicateKeyError

    client = await m365.graph()
    if client is None:
        raise m365.NotConnected("Microsoft 365 is not connected")
    async with client:
        domains = await _verified_domains(client)
        found = await read_message(client, mailbox, message_id, domains)
    event: EventCreate = found["event"]
    if reported_by:
        event.raw_data["reported_by"] = reported_by.get("name")
    try:
        event_id = await EventService().create_event(event)
    except DuplicateKeyError:
        from core.database.connection import get_database
        from core.tenancy import scoped

        existing = await scoped(get_database(), "events").find_one({"raw_data.external_id": event.raw_data["external_id"]})
        return {"event_id": str(existing["_id"]), "alert_id": ((existing.get("metadata") or {}).get("analysis") or {}).get("alert_id"), "already_checked": True}
    alert_id = await analyse_event(event_id, event, {"body": found["body"]})
    return {"event_id": event_id, "alert_id": alert_id, "already_checked": False}
