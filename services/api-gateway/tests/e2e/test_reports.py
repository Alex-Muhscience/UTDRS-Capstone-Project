"""Monthly reports, each test in an organisation of its own so the figures are exact."""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def org(client, monkeypatch):
    """A new organisation's administrator."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"rep_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def raise_alert(client, auth, severity="high", tags=(), title=None, **raw):
    event = client.post(
        f"{API}/events/",
        json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr", "description": "x", "raw_data": raw},
        headers=auth,
    ).json()
    alert = client.post(
        f"{API}/alerts/",
        json={"title": title or f"Alert {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity, "source": "core-engine", "type": "signature",
              "tags": list(tags), "event_ids": [event["id"]]},
        headers=auth,
    ).json()
    from core.services import playbooks

    client.portal.call(playbooks.idle)
    return client.get(f"{API}/alerts/{alert['id']}", headers=auth).json()


def this_month():
    return f"{datetime.now(timezone.utc):%Y-%m}"


def test_a_month_in_figures_and_words(client, org):
    ransomware = raise_alert(client, org, "critical", ["ransomware", "T1490"], title="Shadow copies deleted", hostname="fin-ws-07")
    raise_alert(client, org, "high", ["brute-force", "T1110"], user="jsmith")
    raise_alert(client, org, "medium", ["brute-force", "T1110"], user="jsmith")
    other = raise_alert(client, org, "low", user="ana")
    # One case dealt with, and the ransomware playbook's suggestion approved.
    client.patch(f"{API}/cases/{other['case_id']}", json={"status": "resolved"}, headers=org)
    [suggested] = client.get(f"{API}/response/actions", params={"case_id": ransomware["case_id"]}, headers=org).json()
    client.post(f"{API}/response/actions/{suggested['id']}/approve", headers=org)

    response = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org)
    assert response.status_code == 201, response.text
    data = response.json()["data"]
    f = {k: v["value"] for k, v in data["figures"].items()}
    assert (f["alerts"], f["cases_opened"], f["critical_cases"], f["cases_closed"], f["actions_taken"]) == (4, 3, 1, 1, 1)
    assert f["within_deadline_percent"] == 100 and f["median_hours_to_resolve"] == 0.0
    assert all(v["previous"] in (0, None) for v in data["figures"].values())  # a new organisation had no month before
    assert data["alerts_by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert sum(w["count"] for w in data["weekly_alerts"]) == 4

    assert data["top_threats"][0] == {"name": "Password guessing (brute force)", "count": 2}
    assert {"name": "Deleting backups so files cannot be recovered (a ransomware step)", "count": 1} in data["top_threats"]
    assert {"type": "user", "name": "jsmith", "cases": 1} in data["most_targeted"] and {"type": "device", "name": "fin-ws-07", "cases": 1} in data["most_targeted"]
    assert data["actions"]["taken"] == 1 and data["actions"]["approved"] == 1 and data["actions"]["by_action"] == [{"label": "Raise the case's priority", "count": 1}]

    assert data["outstanding"]["open_cases"] == 2 and data["outstanding"]["top"][0]["title"].startswith("Shadow copies deleted")
    assert data["headline"][0].endswith("raised 4 alerts, grouped into 3 cases, 1 of them critical.")
    assert "1 case was dealt with and 1 response action was taken." in data["headline"]
    assert any("Connect Microsoft 365" in line for line in data["recommendations"])


def test_overdue_cases_and_waiting_actions_are_called_out(client, org):
    alert = raise_alert(client, org, "critical", ["ransomware"], title="Encrypting files", hostname="ws-1")

    async def overdue():
        from bson import ObjectId
        from core.database.connection import get_database

        await get_database()["cases"].update_one({"_id": ObjectId(alert["case_id"])}, {"$set": {"due_at": datetime.now(timezone.utc) - timedelta(hours=1)}})

    client.portal.call(overdue)
    data = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org).json()["data"]
    assert data["outstanding"]["overdue"] == 1 and data["outstanding"]["top"][0]["overdue"] is True
    assert data["recommendations"][0].startswith("Deal with the 1 overdue case, starting with \"Encrypting files")
    assert "Decide on the 1 response action waiting for approval." in data["recommendations"]
    assert data["headline"][-1] == "1 case is still open, 1 overdue."


def test_last_month_is_compared(client, org):
    old = raise_alert(client, org, "high", user="moved")
    raise_alert(client, org, "high", user="stays")

    async def move_to_last_month():
        from bson import ObjectId
        from core.database.connection import get_database

        earlier = datetime.now(timezone.utc).replace(day=1) - timedelta(days=3)
        await get_database()["alerts"].update_one({"_id": ObjectId(old["id"])}, {"$set": {"created_at": earlier}})
        await get_database()["cases"].update_one({"_id": ObjectId(old["case_id"])}, {"$set": {"created_at": earlier}})

    client.portal.call(move_to_last_month)
    data = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org).json()["data"]
    assert data["figures"]["alerts"] == {"value": 1, "previous": 1}
    assert data["figures"]["cases_opened"] == {"value": 1, "previous": 1}


def test_reports_are_kept_listed_and_remade(client, org):
    first = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org).json()
    assert first["data"]["headline"][0].endswith("UTDRS found nothing that needed attention.")
    raise_alert(client, org, "high", user="later")
    again = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org).json()
    assert again["id"] == first["id"] and again["data"]["figures"]["alerts"]["value"] == 1  # one report per month, made again

    listed = client.get(f"{API}/reports/", headers=org).json()
    assert [(r["id"], r["period"]) for r in listed] == [(first["id"], this_month())]
    assert listed[0]["headline"] == again["data"]["headline"]
    assert client.get(f"{API}/reports/{first['id']}", headers=org).json()["data"]["figures"]["alerts"]["value"] == 1


def test_the_report_as_a_pdf(client, org):
    raise_alert(client, org, "high", title="Odd <b>tag & <unclosed", user="x")  # markup in a title stays text
    report = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org).json()
    response = client.get(f"{API}/reports/{report['id']}/pdf", headers=org)
    assert response.status_code == 200 and response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-") and len(response.content) > 2000
    assert response.headers["content-disposition"] == f'attachment; filename="utdrs-report-{this_month()}.pdf"'


def test_months_that_have_not_started_or_do_not_exist(client, org):
    future = datetime.now(timezone.utc) + timedelta(days=40)
    assert client.post(f"{API}/reports/", json={"period": f"{future:%Y-%m}"}, headers=org).status_code == 422
    assert client.post(f"{API}/reports/", json={"period": "2026-13"}, headers=org).status_code == 422
    # With no month given, the last full month.
    made = client.post(f"{API}/reports/", headers=org).json()
    first_of_month = datetime.now(timezone.utc).replace(day=1)
    assert made["period"] == f"{first_of_month - timedelta(days=1):%Y-%m}"


def test_last_months_report_is_made_once_and_administrators_told(client, org):
    from core.services import reports

    me = client.get(f"{API}/auth/me", headers=org).json()
    next_month = (datetime.now(timezone.utc).replace(day=1) + timedelta(days=32)).replace(day=2)
    assert client.portal.call(reports.generate_due, next_month) >= 1
    assert client.portal.call(reports.generate_due, next_month) == 0
    listed = client.get(f"{API}/reports/", headers=org).json()
    assert [r["period"] for r in listed] == [this_month()]

    log = client.get(f"{API}/notifications/", headers=org).json()
    [told] = [n for n in log if n["kind"] == "report_ready"]
    assert told["email"] == me["email"] and told["subject"] == f"[UTDRS] Your security report for {listed[0]['title']}"


def test_an_organisation_that_did_not_exist_gets_no_report_for_that_month(client, org):
    from core.services import reports

    client.portal.call(reports.generate_due, datetime.now(timezone.utc))  # last month: before this organisation
    assert client.get(f"{API}/reports/", headers=org).json() == []


def test_reports_are_kept_within_an_organisation(client, org, monkeypatch):
    report = client.post(f"{API}/reports/", json={"period": this_month()}, headers=org).json()
    username, password = f"rep_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}
    assert client.get(f"{API}/reports/{report['id']}", headers=other).status_code == 404
    assert client.get(f"{API}/reports/{report['id']}/pdf", headers=other).status_code == 404
    assert client.get(f"{API}/reports/", headers=other).json() == []

    key = client.post(f"{API}/api-keys/", json={"name": "k", "scopes": ["alerts:read"]}, headers=org).json()["key"]
    assert client.get(f"{API}/reports/", headers={"Authorization": f"Bearer {key}"}).status_code == 403
