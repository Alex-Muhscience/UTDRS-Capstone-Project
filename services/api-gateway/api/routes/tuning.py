"""Detection tuning: suppressions, detector quality and labels for retraining."""
import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import StreamingResponse

from api.routes.response import actor_of
from core.models.tuning import DetectorQuality, Suppression, SuppressionCreate, SuppressionUpdate
from core.models.user import User
from core.services import audit, tuning
from utils.security import get_current_active_user, require_admin

router = APIRouter()


def _found(suppression):
    if not suppression:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression not found")
    return suppression


def _within_limits(user: User, never_expires: bool, max_severity: Optional[str]) -> None:
    """Only administrators may suppress critical alerts, or suppress for good."""
    if user.role == "admin":
        return
    if never_expires:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an administrator can make a suppression that never expires")
    if max_severity == "critical":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an administrator can suppress critical alerts")


@router.get("/suppressions", response_model=List[Suppression])
async def list_suppressions(current_user: User = Depends(get_current_active_user)):
    """Every suppression, newest first, with how many alerts each has suppressed."""
    return await tuning.list_suppressions()


@router.post("/suppressions", response_model=Suppression, status_code=status.HTTP_201_CREATED)
async def create_suppression(body: SuppressionCreate, request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Suppress alerts like these from now on. Critical alerts get through unless
    `max_severity` is critical, and it expires after `expires_in_days` (90 by default);
    only administrators can lift either limit.
    """
    _within_limits(current_user, body.expires_in_days is None, body.max_severity)
    suppression = await tuning.create_suppression(body.model_dump(), actor_of(request))
    audit.created(request, "suppression", str(suppression["_id"]), suppression["name"])
    return suppression


@router.patch("/suppressions/{suppression_id}", response_model=Suppression)
async def update_suppression(body: SuppressionUpdate, suppression_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """Change a suppression, or turn it off (`enabled`). `expires_in_days` 0 makes it permanent."""
    changes = body.model_dump(exclude_unset=True)
    _within_limits(current_user, changes.get("expires_in_days") == 0, changes.get("max_severity"))
    return _found(await tuning.update_suppression(suppression_id, changes))


@router.delete("/suppressions/{suppression_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_suppression(suppression_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """Delete a suppression. Alerts it suppressed stay as they are."""
    if not await tuning.delete_suppression(suppression_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression not found")


@router.get("/quality", response_model=List[DetectorQuality])
async def detector_quality(days: int = Query(30, ge=1, le=365), current_user: User = Depends(get_current_active_user)):
    """How good each detector has been: noisy ones first, then by number of alerts."""
    return await tuning.quality(days)


@router.get("/labels", response_class=StreamingResponse, responses={200: {"content": {"application/x-ndjson": {}}}})
async def export_labels(since: Optional[datetime] = None, admin: User = Depends(require_admin)):
    """
    Every verdict, as JSON Lines, oldest first: the alert, its detector, the engine's
    findings and the events behind it. For retraining the detection models.
    """

    async def lines():
        async for label in tuning.labels(since):
            yield json.dumps(label, default=str) + "\n"

    return StreamingResponse(lines(), media_type="application/x-ndjson", headers={"Content-Disposition": 'attachment; filename="utdrs-labels.jsonl"'})
