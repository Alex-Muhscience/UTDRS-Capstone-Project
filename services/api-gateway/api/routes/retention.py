"""Data retention: how long your organisation's data is kept (administrators only)."""
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status

from core.models.retention import Retention, RetentionUpdate
from core.models.user import User
from core.services import retention
from utils.security import require_admin

router = APIRouter()


@router.get("/", response_model=Retention)
async def get_retention(admin: User = Depends(require_admin)):
    """How long each kind of data is kept, the deployment's defaults and maximum, and the last clean-up."""
    return await retention.get_settings()


@router.patch("/", response_model=Retention)
async def update_retention(body: RetentionUpdate, admin: User = Depends(require_admin)):
    """Change how long each kind of data is kept, within the deployment's maximum."""
    try:
        return await retention.update_settings(body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(e))


@router.post("/run", response_model=Dict[str, int])
async def run_now(admin: User = Depends(require_admin)):
    """Delete what has passed its time now, rather than at the next hourly clean-up. Returns how much of each kind."""
    return await retention.run()
