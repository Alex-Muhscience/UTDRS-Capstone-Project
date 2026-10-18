"""
UTDRS as an MCP server: AI assistants (Claude, other MCP clients, an organisation's own
agents) investigate and act through UTDRS, with exactly the permissions of the API key
they are given and every change in UTDRS's audit log.

Tools read alerts, cases, events and detection quality; the few that change something
say so (MCP's destructiveHint), and response actions can only be proposed, with an
explicit `confirm`: actions asked for through an API key always wait for a person to
approve them in UTDRS. Answers are trimmed to what an assistant needs.

Run it over Streamable HTTP (`python app.py`, the MCP endpoint at /mcp), with each
client sending a UTDRS API key as its bearer token; or over stdio for a local assistant
(`python server.py`, the key in UTDRS_API_KEY).
"""
import os
from typing import Any, Dict, List, Literal, Optional

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from gateway import call, pick

INSTRUCTIONS = """UTDRS detects threats across an organisation (Microsoft 365 sign-ins and email, devices, network) and responds to them.
Alerts are grouped into cases; start from open cases, read their explanation and evidence, then act: give a verdict on an alert,
update the case, or propose a response action for a person to approve. Never claim an action ran unless its status says so."""

mcp = FastMCP("UTDRS", instructions=INSTRUCTIONS)

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
CHANGE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
PROPOSE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)

ALERT_FIELDS = ("id", "title", "severity", "status", "case_id", "tags", "source", "created_at", "feedback", "suppressed_by")
CASE_FIELDS = ("id", "title", "status", "priority", "owner_id", "breached", "due_at", "first_seen", "last_seen", "entities", "techniques", "alert_ids")
EVENT_FIELDS = ("id", "timestamp", "event_type", "source", "user_id", "source_ip", "description", "raw_data")
MAX_RAW = 1500


def token(ctx: Context) -> str:
    """The caller's UTDRS API key: their bearer token over HTTP, or UTDRS_API_KEY over stdio."""
    request = getattr(ctx.request_context, "request", None)
    if request is not None:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        raise ToolError("Send a UTDRS API key as the bearer token")
    key = os.environ.get("UTDRS_API_KEY")
    if not key:
        raise ToolError("Set UTDRS_API_KEY to a UTDRS API key")
    return key


def _event(event: Dict[str, Any]) -> Dict[str, Any]:
    out = pick(event, *EVENT_FIELDS)
    raw = out.get("raw_data") or {}
    text = str(raw)
    if len(text) > MAX_RAW:  # keep answers small; the full event is in UTDRS
        out["raw_data"] = {k: v for k, v in list(raw.items())[:20]}
        out["truncated"] = True
    return out


# ---------------------------------------------------------------------------- Reading


@mcp.tool(annotations=READ)
async def list_cases(
    ctx: Context, status: Optional[Literal["open", "investigating", "contained", "resolved", "false_positive", "closed"]] = None,
    open_only: bool = True, limit: int = 20,
) -> List[Dict[str, Any]]:
    """Cases (related alerts grouped together), most recently active first. By default only those still being worked."""
    params: Dict[str, Any] = {"limit": min(max(limit, 1), 100)}
    if status:
        params["status"] = status
    elif open_only:
        params["open_only"] = True
    return [pick(c, *CASE_FIELDS) for c in await call(token(ctx), "GET", "/cases/", params=params)]


@mcp.tool(annotations=READ)
async def get_case(ctx: Context, case_id: str) -> Dict[str, Any]:
    """One case: its plain-language explanation (what happened, why it matters, what to do), timeline and the people and devices involved."""
    case = await call(token(ctx), "GET", f"/cases/{case_id}")
    out = pick(case, *CASE_FIELDS, "explanation")
    out["timeline"] = [pick(e, "at", "kind", "text") for e in (case.get("timeline") or [])[-30:]]
    return out


@mcp.tool(annotations=READ)
async def get_case_evidence(ctx: Context, case_id: str) -> Dict[str, Any]:
    """The alerts in a case and the events behind them, oldest first."""
    evidence = await call(token(ctx), "GET", f"/cases/{case_id}/evidence")
    return {
        "alerts": [pick(a, *ALERT_FIELDS) for a in evidence.get("alerts", [])[:50]],
        "events": [_event(e) for e in evidence.get("events", [])[:50]],
        "entities": evidence.get("entities", []),
    }


@mcp.tool(annotations=READ)
async def list_alerts(
    ctx: Context, status: Optional[Literal["open", "in_progress", "resolved", "closed", "false_positive", "suppressed"]] = None,
    severity: Optional[Literal["critical", "high", "medium", "low", "info"]] = None, limit: int = 20,
) -> List[Dict[str, Any]]:
    """Alerts, newest first, optionally by status and severity."""
    params = {k: v for k, v in {"status": status, "severity": severity, "limit": min(max(limit, 1), 100)}.items() if v}
    return [pick(a, *ALERT_FIELDS) for a in await call(token(ctx), "GET", "/alerts/", params=params)]


@mcp.tool(annotations=READ)
async def get_alert(ctx: Context, alert_id: str) -> Dict[str, Any]:
    """One alert, with what the detection engine found (techniques, model, rule)."""
    alert = await call(token(ctx), "GET", f"/alerts/{alert_id}")
    out = pick(alert, *ALERT_FIELDS, "description", "event_ids")
    details = ((alert.get("metadata") or {}).get("details") or {})
    out["detection"] = {k: details.get(k) for k in ("mitre_techniques", "rule_name", "model", "confidence", "provider") if details.get(k)}
    return out


@mcp.tool(annotations=READ)
async def search_events(ctx: Context, query: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Events whose description or details mention `query` (a user, address, host, process...), newest first."""
    return [_event(e) for e in await call(token(ctx), "GET", "/events/search/", params={"query": query, "limit": min(max(limit, 1), 100)})]


@mcp.tool(annotations=READ)
async def list_pending_actions(ctx: Context) -> List[Dict[str, Any]]:
    """Response actions waiting for a person's decision in UTDRS."""
    actions = await call(token(ctx), "GET", "/response/actions", params={"status": "pending", "limit": 50})
    return [pick(a, "id", "label", "action", "target", "reason", "case_id", "created_at", "requested_by") for a in actions]


@mcp.tool(annotations=READ)
async def list_response_actions(ctx: Context) -> List[Dict[str, Any]]:
    """The response actions UTDRS can take, what each acts on, and whether the service it needs is connected."""
    return [pick(a, "name", "label", "description", "target", "params", "can_undo", "connected") for a in await call(token(ctx), "GET", "/response/actions/types")]


@mcp.tool(annotations=READ)
async def detector_quality(ctx: Context, days: int = 30) -> List[Dict[str, Any]]:
    """How good each detector has been: alerts, verdicts and precision; noisy ones first."""
    return await call(token(ctx), "GET", "/tuning/quality", params={"days": min(max(days, 1), 365)})


# ---------------------------------------------------------------------------- Changing


@mcp.tool(annotations=CHANGE)
async def update_case(
    ctx: Context, case_id: str,
    status: Optional[Literal["open", "investigating", "contained", "resolved", "false_positive", "closed"]] = None,
    priority: Optional[Literal["critical", "high", "medium", "low", "info"]] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    """Change a case's status or priority, and/or add a note to its timeline. Resolving or closing it closes its open alerts."""
    key = token(ctx)
    changes = {k: v for k, v in {"status": status, "priority": priority}.items() if v}
    if not changes and not note:
        raise ToolError("Give a status, a priority or a note")
    case = None
    if changes:
        case = await call(key, "PATCH", f"/cases/{case_id}", json=changes)
    if note:
        case = await call(key, "POST", f"/cases/{case_id}/notes", json={"text": note[:5000]})
    return pick(case or {}, *CASE_FIELDS)


@mcp.tool(annotations=CHANGE)
async def give_verdict(
    ctx: Context, alert_id: str, verdict: Literal["true_positive", "false_positive", "benign"], note: Optional[str] = None,
) -> Dict[str, Any]:
    """Say whether an alert was a real threat, a false positive, or real but expected activity. It tunes detection."""
    result = await call(token(ctx), "POST", f"/alerts/{alert_id}/feedback", json={"verdict": verdict, "note": note})
    return {"alert": pick(result["alert"], *ALERT_FIELDS), "suggested_suppression": result.get("suggestion")}


@mcp.tool(annotations=PROPOSE)
async def propose_action(
    ctx: Context, action: str, target_type: Literal["user", "message", "case"], target_value: str,
    confirm: bool, params: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Propose a response action (see list_response_actions), such as signing a user out
    everywhere or removing a phishing email. It is not run: it waits for a person to
    approve it in UTDRS. Set confirm to true only when the user has agreed to propose it.
    """
    if not confirm:
        raise ToolError("Not proposed: set confirm to true once the user has agreed")
    body = {"action": action, "target": {"type": target_type, "value": target_value}, "params": params or {}, "case_id": case_id}
    proposed = await call(token(ctx), "POST", "/response/actions", json=body)
    return pick(proposed, "id", "label", "status", "reason", "target", "case_id")


@mcp.tool(annotations=CHANGE)
async def check_email(ctx: Context, recipient: str, internet_message_id: str) -> Dict[str, Any]:
    """Check a delivered email for phishing (headers, links, attachments and the phishing model), from the recipient's mailbox."""
    key = token(ctx)
    result = await call(key, "POST", "/email/check", json={"recipient": recipient, "internet_message_id": internet_message_id})
    event = await call(key, "GET", f"/events/{result['event_id']}")
    alert = await call(key, "GET", f"/alerts/{result['alert_id']}") if result.get("alert_id") else None
    return {"looks_malicious": bool(alert), "alert": pick(alert, *ALERT_FIELDS) if alert else None, "email": _event(event), "already_checked": result["already_checked"]}


# ---------------------------------------------------------------------------- Resources and prompts


@mcp.resource("utdrs://cases/{case_id}", mime_type="application/json")
async def case_resource(case_id: str) -> Dict[str, Any]:
    """A case, to attach as context."""
    return await get_case(mcp.get_context(), case_id)


@mcp.resource("utdrs://alerts/{alert_id}", mime_type="application/json")
async def alert_resource(alert_id: str) -> Dict[str, Any]:
    """An alert, to attach as context."""
    return await get_alert(mcp.get_context(), alert_id)


@mcp.prompt()
def triage_open_cases() -> str:
    """Work through the open cases, most urgent first."""
    return ("List the open UTDRS cases. For the most urgent one, read it and its evidence, decide whether it is a real threat, "
            "and say what to do. Propose a response action only if I agree, and give verdicts on alerts you are sure about.")


@mcp.prompt()
def investigate_case(case_id: str) -> str:
    """Investigate one case thoroughly."""
    return (f"Investigate UTDRS case {case_id}: read its explanation, timeline and evidence; search for related events about the "
            "people, devices and addresses involved; then tell me what happened, how sure you are, and what to do next.")


@mcp.prompt()
def explain_to_customer(case_id: str) -> str:
    """Explain a case to someone who is not technical."""
    return f"Read UTDRS case {case_id} and explain it in plain words for a business owner: what happened, whether they are safe, and what we did."


if __name__ == "__main__":
    mcp.run("stdio")
