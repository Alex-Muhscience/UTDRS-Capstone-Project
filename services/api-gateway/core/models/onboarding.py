from typing import Dict, List

from pydantic import BaseModel


class Step(BaseModel):
    # name, microsoft_365, response, team, email, results
    key: str
    title: str
    done: bool
    detail: str
    optional: bool = False
    # Done, but something is wrong (a connection with errors).
    attention: bool = False


class Onboarding(BaseModel):
    steps: List[Step]
    done: int
    total: int
    # Every step that is not optional is done.
    complete: bool
    # An administrator put the checklist away.
    dismissed: bool
    # The last day: events, Microsoft 365 sign-ins, alerts; open cases and reports.
    results: Dict[str, int]


class OnboardingUpdate(BaseModel):
    dismissed: bool
