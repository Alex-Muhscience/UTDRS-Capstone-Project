"""The audit log (administrators only)."""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query

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
