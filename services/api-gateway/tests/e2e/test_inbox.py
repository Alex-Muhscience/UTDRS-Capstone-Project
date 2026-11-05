"""The notifications centre: each person's inbox."""
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from tests.e2e.test_live import a_minute_ago, read, short_streams  # noqa: F401  (fixture)
from tests.e2e.test_platform import key, sign_up  # noqa: F401  (fixture)
from tests.e2e.test_roles import person

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def alert(client, auth, severity):
    return client.post(f"{API}/alerts/", json={"title": f"{severity} {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity,
                                               "source": "x", "type": "x"}, headers=auth).json()


def items(client, auth, **params):
    return client.get(f"{API}/inbox", params=params, headers=auth).json()


def kinds(client, auth):
    return [i["kind"] for i in items(client, auth)["items"]]


def test_serious_alerts_reach_those_who_may_see_them(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "ia")
    analyst, _ = person(client, admin, "analyst")
    viewer, _ = person(client, admin, "viewer")
    cases_only = client.post(f"{API}/roles", json={"name": "Cases only", "permissions": ["cases:read"]}, headers=admin).json()
    blind, _ = person(client, admin, "custom", cases_only["id"])

    alert(client, admin, "low")
    assert "alert" not in kinds(client, analyst)  # not worth interrupting anyone
    serious = alert(client, admin, "critical")
    found = next(i for i in items(client, analyst)["items"] if i["kind"] == "alert")
    assert found["title"].startswith("New critical alert") and found["link"] == f"/alerts/{serious['id']}" and not found["read"]
    assert "alert" in kinds(client, viewer) and "alert" in kinds(client, admin)
    assert "alert" not in kinds(client, blind)  # their role does not include alerts
    assert client.get(f"{API}/inbox/unread", headers=analyst).json()["unread"] >= 1


def test_people_mark_their_own_notifications_read(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "ib")
    analyst, _ = person(client, admin, "analyst")
    alert(client, admin, "high")
    alert(client, admin, "high")
    mine = items(client, analyst, unread_only=True)["items"]
    theirs = items(client, admin, unread_only=True)["items"]
    assert len(mine) >= 2
    # Someone else's item cannot be marked read by me.
    assert client.post(f"{API}/inbox/read", json={"ids": [theirs[0]["id"]]}, headers=analyst).status_code == 200
    assert not next(i for i in items(client, admin)["items"] if i["id"] == theirs[0]["id"])["read"]

    left = client.post(f"{API}/inbox/read", json={"ids": [mine[0]["id"]]}, headers=analyst).json()["unread"]
    assert left == len(mine) - 1
    assert client.post(f"{API}/inbox/read", json={}, headers=analyst).json()["unread"] == 0
    assert items(client, analyst, unread_only=True)["items"] == []
    viewer, _ = person(client, admin, "viewer")
    assert client.post(f"{API}/inbox/read", json={}, headers=viewer).status_code == 200  # read-only people may still tidy their inbox


def test_people_hear_when_work_is_assigned_to_them_by_someone_else(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "ic")
    analyst, analyst_account = person(client, admin, "analyst")
    me = client.get(f"{API}/auth/me", headers=admin).json()
    raised = alert(client, admin, "medium")
    client.patch(f"{API}/alerts/{raised['id']}/assign", params={"assigned_to": analyst_account["id"]}, headers=admin)
    got = next(i for i in items(client, analyst)["items"] if i["kind"] == "alert_assigned")
    assert me["username"] in got["title"] and got["link"] == f"/alerts/{raised['id']}"

    case_id = client.get(f"{API}/alerts/{raised['id']}", headers=admin).json()["case_id"]
    client.patch(f"{API}/cases/{case_id}", json={"owner_id": analyst_account["id"]}, headers=admin)
    assert "case_assigned" in kinds(client, analyst)
    # Taking something yourself tells nobody.
    client.patch(f"{API}/alerts/{raised['id']}/assign", params={"assigned_to": me["id"]}, headers=admin)
    assert "alert_assigned" not in kinds(client, admin)


def test_decisions_failures_reports_and_connectors(client, monkeypatch):
    from core.services import inbox
    from core.tenancy import tenant_context

    _, admin = sign_up(client, monkeypatch, "id")
    analyst, analyst_account = person(client, admin, "analyst")
    viewer, _ = person(client, admin, "viewer")
    tenant_id = client.get(f"{API}/tenants/current", headers=admin).json()["id"]

    async def events():
        with tenant_context(tenant_id):
            await inbox.from_event("action.approval_requested", {"id": "a1", "action": "disable_account", "target": {"type": "account", "value": "bob@x"},
                                                                 "protected": False, "url": "https://utdrs.example/response"})
            await inbox.from_event("action.approval_requested", {"id": "a2", "action": "disable_account", "target": {"type": "account", "value": "boss@x"},
                                                                 "protected": True, "url": "https://utdrs.example/response"})
            await inbox.from_event("action.completed", {"id": "a3", "action": "disable_account", "target": {"type": "account", "value": "eve@x"},
                                                        "status": "succeeded", "summary": "Disabled", "requested_by": {"type": "user", "id": analyst_account["id"]}})
            await inbox.from_event("report.ready", {"id": "r1", "title": "October", "headline": "Quiet", "url": "https://utdrs.example/reports/r1"})
            await inbox.from_event("connector.unhealthy", {"connector": "microsoft-365", "errors": ["401"], "url": "https://utdrs.example/connectors"})

    client.portal.call(events)
    approvals = [i for i in items(client, analyst)["items"] if i["kind"] == "approval"]
    assert [a["target"]["id"] for a in approvals] == ["a1"] and approvals[0]["link"] == "/response"  # protected accounts are administrators'
    assert sorted(i["target"]["id"] for i in items(client, admin)["items"] if i["kind"] == "approval") == ["a1", "a2"]
    assert "approval" not in kinds(client, viewer)  # cannot decide
    assert "action_done" in kinds(client, analyst) and "action_done" not in kinds(client, admin)  # the requester's own
    assert {"report", "connector"} <= set(kinds(client, admin)) and not {"report", "connector"} & set(kinds(client, analyst))


def test_inboxes_are_personal(client, monkeypatch):
    _, admin = sign_up(client, monkeypatch, "ie")
    analyst, analyst_account = person(client, admin, "analyst")
    raised = alert(client, admin, "low")
    since = a_minute_ago()
    client.patch(f"{API}/alerts/{raised['id']}/assign", params={"assigned_to": analyst_account["id"]}, headers=admin)
    assert "inbox.created" in [e for _, e, _ in read(client, analyst, last_event_id=since)]
    assert "inbox.created" not in [e for _, e, _ in read(client, admin, last_event_id=since)]
    key_value = client.post(f"{API}/api-keys/", json={"name": "k", "scopes": ["alerts:read"]}, headers=admin).json()["key"]
    assert client.get(f"{API}/inbox", headers={"Authorization": f"Bearer {key_value}"}).status_code == 403
