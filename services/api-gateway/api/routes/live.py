"""The live updates stream (Server-Sent Events): what changed in your organisation, as it happens."""
import asyncio
import json
import time
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import StreamingResponse

from core.models.user import User
from core.services import live
from utils.security import get_current_active_user

router = APIRouter()

# A stream ends after this long and the dashboard reconnects, so a session that was ended,
# a person deactivated or an organisation suspended stops receiving within it.
STREAM_SECONDS = 300
HEARTBEAT_SECONDS = 15.0
# What a person must be allowed to see to hear of each kind of change.
PERMISSION_FOR = {"alert": "alerts:read", "case": "cases:read", "action": "response:read", "report": "reports:read"}


def _frame(message: Dict[str, Any]) -> str:
    if message["event"] == "inbox.created":
        message = {**message, "data": {}}  # whose inbox it was is not for others to read
    lines = [f"event: {message['event']}"]
    if message.get("id"):
        lines.insert(0, f"id: {message['id']}")
    lines.append(f"data: {json.dumps(message.get('data') or {}, default=str)}")
    return "\n".join(lines) + "\n\n"


@router.get(
    "",
    summary="Live updates",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}, "description": "Server-Sent Events: alert.created, alert.updated, case.created, "
                     "case.updated, action.approval_requested, action.completed, report.ready, connector.unhealthy, and resync."}},
)
async def stream(request: Request, current_user: User = Depends(get_current_active_user),
                 last_event_id: Optional[str] = Header(None, alias="Last-Event-ID")) -> StreamingResponse:
    """
    Changes in your organisation as Server-Sent Events. Each says what changed (with an alert's
    title and severity); fetch the details through the API. Send `Last-Event-ID` when reconnecting
    to get what you missed; `resync` means fetch everything again. The stream ends every few
    minutes; reconnect.
    """
    tenant_id = current_user.tenant_id
    allowed = current_user.permissions  # a custom role hears only of what it may see

    def may_hear(message: Dict[str, Any]) -> bool:
        if message["event"] == "inbox.created":
            return current_user.id in (message.get("data") or {}).get("users", [])
        area = PERMISSION_FOR.get(message["event"].split(".")[0])
        return allowed is None or area is None or area in allowed

    async def events() -> AsyncIterator[str]:
        queue = live.hub.subscribe(tenant_id)
        try:
            yield "retry: 5000\n\n"
            yield _frame({"event": "ready", "data": {}})
            if last_event_id:
                for message in await live.missed(tenant_id, last_event_id):
                    if may_hear(message):
                        yield _frame(message)
            deadline = time.monotonic() + STREAM_SECONDS
            while time.monotonic() < deadline:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=min(HEARTBEAT_SECONDS, max(0.01, deadline - time.monotonic())))
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                if may_hear(message):
                    yield _frame(message)
        finally:
            live.hub.unsubscribe(tenant_id, queue)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
