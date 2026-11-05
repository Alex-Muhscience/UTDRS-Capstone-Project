"""The audit log (administrators only)."""
import csv
import io
import json
from datetime import datetime
from typing import AsyncIterator, List, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from core.models.audit import AuditEntry, AuditVerification
from core.models.user import User
from core.services import audit
from utils.security import require_admin

router = APIRouter()


@router.get("/", response_model=List[AuditEntry])
async def search_audit_log(
    action: Optional[str] = Query(None, description="An action (rule.updated), or a kind of action (rule)"),
    actor_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(100, ge=1, le=500),
    skip: int = Query(0, ge=0),
    admin: User = Depends(require_admin),
):
    """Audit entries, newest first."""
    return await audit.search(
        action=action, actor_id=actor_id, target_type=target_type, target_id=target_id,
        since=since, until=until, limit=limit, skip=skip,
    )


@router.get("/verify", response_model=AuditVerification)
async def verify_audit_log(admin: User = Depends(require_admin)):
    """Check that no entry has been altered, inserted or removed since it was written."""
    return await audit.verify()


CSV_COLUMNS = ["seq", "at", "action", "outcome", "actor_type", "actor_id", "actor_name", "address", "request_id",
               "target_type", "target_id", "target_name", "changes", "details", "prev_hash", "hash"]


def _csv_row(entry: dict) -> list:
    line = json.loads(audit.export_line(entry))  # times as they were hashed
    actor, target = line.get("actor") or {}, line.get("target") or {}
    as_json = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False) if value is not None else ""  # noqa: E731
    return [line.get("seq"), line.get("at"), line.get("action"), line.get("outcome"), actor.get("type"), actor.get("id"), actor.get("name"),
            line.get("address"), line.get("request_id"), target.get("type"), target.get("id"), target.get("name"),
            as_json(line.get("changes")), as_json(line.get("details")), line.get("prev_hash"), line.get("hash")]


@router.get("/export", responses={200: {"content": {"application/x-ndjson": {}, "text/csv": {}}}})
async def export_audit_log(
    request: Request,
    format: Literal["jsonl", "csv"] = "jsonl",
    action: Optional[str] = Query(None, description="An action (rule.updated), or a kind of action (rule)"),
    actor_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    admin: User = Depends(require_admin),
):
    """
    Download the audit log, oldest first, as JSON Lines (each line exactly what was
    hashed, with `prev_hash` and `hash`, so the chain can be checked outside UTDRS with
    scripts/verify_audit_export.py) or CSV (for spreadsheets). The same filters as the search.
    """
    filters = {"action": action, "actor_id": actor_id, "target_type": target_type, "target_id": target_id, "since": since, "until": until}
    await audit.record("audit.exported", request, details={"format": format, **{k: v for k, v in filters.items() if v is not None}})

    async def jsonl() -> AsyncIterator[str]:
        async for entry in audit.entries(**filters):
            yield audit.export_line(entry) + "\n"

    async def rows() -> AsyncIterator[str]:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_COLUMNS)
        async for entry in audit.entries(**filters):
            writer.writerow(_csv_row(entry))
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
        yield buffer.getvalue()

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    media = "application/x-ndjson" if format == "jsonl" else "text/csv; charset=utf-8"
    return StreamingResponse(jsonl() if format == "jsonl" else rows(), media_type=media,
                             headers={"Content-Disposition": f'attachment; filename="utdrs-audit-{stamp}.{format}"'})
