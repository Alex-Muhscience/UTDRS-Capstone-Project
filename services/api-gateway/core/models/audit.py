from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel


class AuditEntry(BaseModel):
    seq: int
    at: datetime
    # What happened, as <thing>.<verb>: auth.login_succeeded, rule.updated, api_key.created, ...
    action: str
    # success, or denied / failed when the attempt did not go through.
    outcome: str
    # Who: {type: user | api_key | service | anonymous, id, name, ...}
    actor: Dict[str, Any]
    address: Optional[str] = None
    request_id: Optional[str] = None
    # What it was done to: {type, id, name}
    target: Optional[Dict[str, Any]] = None
    # What changed: {field: [before, after]}
    changes: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    prev_hash: str
    hash: str


class AuditVerification(BaseModel):
    ok: bool
    # How many entries were checked, from the first.
    checked: int
    problem: Optional[str] = None
    # Set when the newest entries are still being written, so the end could not be checked.
    note: Optional[str] = None
