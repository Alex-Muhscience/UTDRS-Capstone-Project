"""
Onboarding: from a new organisation to its first results, the same day.

The checklist is worked out from the organisation's actual state, not kept as ticks, so
a step done anywhere (the Connectors page, the Users page) counts, and undoing it (say,
disconnecting Microsoft 365) shows it again. Only what cannot be seen any other way is
recorded on the organisation: that email was tested, and that the checklist was put away.
"""
from datetime import timedelta
from typing import Any, Dict, List

from bson import ObjectId

from config import settings
from core.database.connection import get_database
from core.services import m365, notifications, tenants
from core.tenancy import current_tenant, scoped
from utils.time import utcnow


async def _record(**fields) -> None:
    await get_database()["tenants"].update_one(
        {"_id": ObjectId(current_tenant())}, {"$set": {f"onboarding.{k}": v for k, v in fields.items()}}
    )


async def email_tested() -> None:
    await _record(email_tested_at=utcnow())


async def dismiss(dismissed: bool) -> None:
    await _record(dismissed_at=utcnow() if dismissed else None)


async def first_results() -> Dict[str, Any]:
    """What UTDRS has seen and done for the organisation in the last day."""
    database = get_database()
    since = utcnow() - timedelta(days=1)
    return {
        "events": await scoped(database, "events").count_documents({"created_at": {"$gte": since}}),
        "sign_ins": await scoped(database, "events").count_documents({"created_at": {"$gte": since}, "source": "m365", "event_type": "authentication"}),
        "alerts": await scoped(database, "alerts").count_documents({"created_at": {"$gte": since}, "status": {"$ne": "suppressed"}}),
        "open_cases": await scoped(database, "cases").count_documents({"status": {"$in": ["open", "investigating", "contained"]}}),
        "reports": await scoped(database, "reports").count_documents({}),
    }


async def status() -> Dict[str, Any]:
    tenant = await tenants.get(current_tenant()) or {}
    state = tenant.get("onboarding") or {}
    connection = await m365.get_connection()
    people = await scoped(get_database(), "users").count_documents({"active": True})
    results = await first_results()

    steps: List[Dict[str, Any]] = [
        {
            "key": "name",
            "title": "Name your organisation",
            "done": tenant.get("name") != settings.DEFAULT_TENANT_NAME,
            "detail": f"Called {tenant.get('name')}" if tenant.get("name") != settings.DEFAULT_TENANT_NAME else "Reports and emails will use this name",
        },
        {
            "key": "microsoft_365",
            "title": "Connect Microsoft 365",
            "done": bool(connection),
            "detail": (
                f"Connected{' to ' + connection['organisation_name'] if connection.get('organisation_name') else ''}"
                + (": needs attention" if connection.get("status") == "error" else "")
                if connection else "So UTDRS can watch sign-ins and Defender alerts, and act on accounts and email"
            ),
            "attention": bool(connection and connection.get("status") == "error"),
        },
        {
            "key": "response",
            "title": "Choose how UTDRS responds",
            "done": "response" in tenant,
            "detail": {"automatic": "Playbooks act on their own, within the safety limits", "approval": "Playbooks ask before acting",
                       "notify": "Playbooks only suggest"}.get((tenant.get("response") or {}).get("mode", ""), "Ask before acting, act on its own, or only suggest"),
        },
        {
            "key": "team",
            "title": "Invite your team",
            "done": people > 1,
            "optional": True,
            "detail": f"{people} people" if people > 1 else "Add the people who look after security, or skip this if it is just you",
        },
        {
            "key": "email",
            "title": "Check email works",
            "done": bool(state.get("email_tested_at")),
            "optional": True,
            "detail": (
                "A test email arrived" if state.get("email_tested_at")
                else "Send yourself a test email, so you hear about urgent cases" if notifications.configured()
                else "Email is not set up on this UTDRS yet (SMTP settings)"
            ),
        },
        {
            "key": "results",
            "title": "See your first results",
            "done": results["events"] > 0,
            "detail": (
                f"{results['events']} events in the last day, {results['alerts']} alerts, {results['open_cases']} open cases"
                if results["events"] else "Results appear within minutes of connecting Microsoft 365"
            ),
        },
    ]
    for step in steps:
        step.setdefault("optional", False)
        step.setdefault("attention", False)
    required = [s for s in steps if not s["optional"]]
    return {
        "steps": steps,
        "done": sum(s["done"] for s in steps),
        "total": len(steps),
        "complete": all(s["done"] for s in required),
        "dismissed": bool(state.get("dismissed_at")),
        "results": results,
    }
