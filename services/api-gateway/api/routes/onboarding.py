"""Onboarding: the checklist from a new organisation to its first results."""
from fastapi import APIRouter, Depends

from core.models.onboarding import Onboarding, OnboardingUpdate
from core.models.user import User
from core.services import onboarding
from utils.security import get_current_active_user, require_admin

router = APIRouter()


@router.get("/", response_model=Onboarding)
async def get_onboarding(current_user: User = Depends(get_current_active_user)):
    """What is set up, what is left, and the first results. Worked out from the organisation's state."""
    return await onboarding.status()


@router.patch("/", response_model=Onboarding)
async def update_onboarding(body: OnboardingUpdate, admin: User = Depends(require_admin)):
    """Put the checklist away (or bring it back). Administrators only."""
    await onboarding.dismiss(body.dismissed)
    return await onboarding.status()
