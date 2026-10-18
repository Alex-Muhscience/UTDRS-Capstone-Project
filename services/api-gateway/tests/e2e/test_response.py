"""Response actions and playbooks, against a stand-in for Microsoft Graph."""
import json
import os
import secrets
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
GLOBAL_ADMIN_MEMBERS = "/v1.0/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members"


class FakeGraph:
    """Just enough of Microsoft Graph: users, the Global Administrators, inbox rules and messages."""

    def __init__(self):
        self.calls = []
        self.users = {}
        self.global_admins = ["it-admin@contoso.example"]
        self.rules = {}  # (mailbox, rule id) -> rule
        self.messages = {}  # (mailbox, id) -> message

    def user(self, upn):
        return self.users.setdefault(upn, {"accountEnabled": True, "sessions_revoked": 0, "forceChange": False})

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else None
        self.calls.append((method, path))
        parts = path.removeprefix("/v1.0/").split("/")
        if path == GLOBAL_ADMIN_MEMBERS:
            return httpx.Response(200, json={"value": [{"id": f"id-{a}", "userPrincipalName": a, "accountEnabled": self.user(a)["accountEnabled"]} for a in self.global_admins]})
        if parts[0] != "users":
            return httpx.Response(404, json={"error": {"code": "NotFound", "message": "Not found"}})
        upn = parts[1]
        if len(parts) == 2 and method == "PATCH":
            if "accountEnabled" in body:
                self.user(upn)["accountEnabled"] = body["accountEnabled"]
            if "passwordProfile" in body:
                self.user(upn)["forceChange"] = body["passwordProfile"]["forceChangePasswordNextSignIn"]
            return httpx.Response(204)
        if parts[2:] == ["revokeSignInSessions"]:
            self.user(upn)["sessions_revoked"] += 1
            return httpx.Response(200, json={"value": True})
        if parts[2:5] == ["mailFolders", "inbox", "messageRules"]:
            if len(parts) == 5 and method == "POST":
                rule_id = f"rule-{len(self.rules) + 1}"
                self.rules[(upn, rule_id)] = {**body, "id": rule_id}
                return httpx.Response(201, json=self.rules[(upn, rule_id)])
            key = (upn, parts[5])
            if key not in self.rules:
                return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound", "message": "The rule was not found"}})
            if method == "GET":
                return httpx.Response(200, json={**self.rules[key], "@odata.context": "x", "isReadOnly": False, "hasError": False})
            del self.rules[key]
            return httpx.Response(204)
        if parts[2] == "messages" and len(parts) == 3:
            wanted = request.url.params["$filter"].split("'")[1]
            found = [{"id": i, "parentFolderId": m["folder"]} for (box, i), m in self.messages.items() if box == upn and m["internetMessageId"] == wanted and m["folder"] != "recoverableitemsdeletions"]
            return httpx.Response(200, json={"value": found})
        if parts[2] == "messages" and parts[4:] == ["move"]:
            message = self.messages.pop((upn, parts[3]))
            new_id = f"{parts[3]}-moved"
            self.messages[(upn, new_id)] = {**message, "folder": body["destinationId"]}
            return httpx.Response(201, json={"id": new_id})
        return httpx.Response(400, json={"error": {"code": "BadRequest", "message": f"Unexpected {method} {path}"}})


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def graph():
    """Microsoft 365, connected for every organisation, as the stand-in."""
    from core.services import connectors

    fake = FakeGraph()

    async def factory():
        return httpx.AsyncClient(base_url="https://graph.microsoft.com/v1.0", transport=httpx.MockTransport(fake.handler))

    previous = connectors._factories.get("m365")
    connectors.register("m365", factory)
    yield fake
    if previous:
        connectors.register("m365", previous)
    else:
        connectors.unregister("m365")


@pytest.fixture(scope="module")
def admin(client):
    response = client.post(f"{API}/auth/login", data={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="module")
def analyst(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"resp_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"resp_{suffix}@example.com"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}


@pytest.fixture(autouse=True)
def restore_settings(client, admin):
    """Each test starts from the defaults: approval mode, built-in playbooks as shipped."""
    yield
    idle(client)
    client.patch(f"{API}/response/settings", json={"mode": "approval", "max_actions_per_hour": 20, "protected_accounts": []}, headers=admin)
    for playbook in client.get(f"{API}/playbooks/", headers=admin).json():
        if playbook["built_in"]:
            client.patch(f"{API}/playbooks/{playbook['id']}", json={"enabled": True, "mode": "approval"}, headers=admin)


def idle(client):
    from core.services import playbooks

    client.portal.call(playbooks.idle)


def raise_alert(client, auth, severity="high", tags=(), **raw):
    event = client.post(
        f"{API}/events/",
        json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "authentication", "source": "m365", "description": "x", "raw_data": raw},
        headers=auth,
    ).json()
    alert = client.post(
        f"{API}/alerts/",
        json={"title": f"Alert {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity, "source": "core-engine", "type": "signature",
              "tags": list(tags), "event_ids": [event["id"]]},
        headers=auth,
    ).json()
    idle(client)
    return client.get(f"{API}/alerts/{alert['id']}", headers=auth).json()


def actions_of(client, auth, case_id):
    return client.get(f"{API}/response/actions", params={"case_id": case_id}, headers=auth).json()


def built_in(client, auth, key):
    return next(p for p in client.get(f"{API}/playbooks/", headers=auth).json() if p["built_in"] == key)


def upn():
    return f"user-{uuid.uuid4().hex[:6]}@contoso.example"


def test_the_actions_on_offer_say_what_is_connected(client, admin):
    types = {t["name"]: t for t in client.get(f"{API}/response/actions/types", headers=admin).json()}
    assert types["m365.disable_account"]["connected"] is False and types["m365.disable_account"]["can_undo"] is True
    assert types["utdrs.escalate_case"]["connected"] is True
    assert "m365.restore_message" not in types  # only for undoing


def test_disabling_an_account_and_undoing_it(client, admin, graph):
    user = upn()
    response = client.post(f"{API}/response/actions", json={"action": "m365.disable_account", "target": {"type": "user", "value": user}}, headers=admin)
    assert response.status_code == 201, response.text
    action = response.json()
    assert action["status"] == "succeeded" and action["can_undo"] and graph.user(user)["accountEnabled"] is False

    undo = client.post(f"{API}/response/actions/{action['id']}/undo", headers=admin).json()
    assert undo["action"] == "m365.enable_account" and undo["status"] == "succeeded" and undo["undoes"] == action["id"]
    assert graph.user(user)["accountEnabled"] is True
    original = client.get(f"{API}/response/actions/{action['id']}", headers=admin).json()
    assert original["status"] == "undone" and original["undone_by"] == undo["id"] and not original["can_undo"]
    assert client.post(f"{API}/response/actions/{action['id']}/undo", headers=admin).status_code == 409

    log = client.get(f"{API}/audit-log/", params={"target_id": user}, headers=admin).json()
    assert {e["action"] for e in log} >= {"response.action_succeeded"}
    assert any(e["details"]["action"] == "m365.enable_account" for e in log if e["action"] == "response.action_succeeded")


def test_the_last_global_administrator_is_never_disabled(client, admin, graph):
    action = client.post(f"{API}/response/actions", json={"action": "m365.disable_account", "target": {"type": "user", "value": "it-admin@contoso.example"}}, headers=admin).json()
    assert action["status"] == "failed" and "last enabled Global Administrator" in action["error"]
    assert graph.user("it-admin@contoso.example")["accountEnabled"] is True
    graph.global_admins.append("second-admin@contoso.example")
    assert client.post(f"{API}/response/actions", json={"action": "m365.disable_account", "target": {"type": "user", "value": "it-admin@contoso.example"}}, headers=admin).json()["status"] == "succeeded"


def test_a_playbook_proposes_and_people_decide(client, admin, graph):
    user = upn()
    alert = raise_alert(client, admin, "high", ["brute-force"], user=user)
    proposed = actions_of(client, admin, alert["case_id"])
    assert sorted(a["action"] for a in proposed) == ["m365.require_password_change", "m365.revoke_sessions"]
    assert all(a["status"] == "pending" and a["mode"] == "approval" and a["playbook"]["name"] == "Account takeover" for a in proposed)
    assert graph.user(user)["sessions_revoked"] == 0  # nothing happens before a person says so

    revoke = next(a for a in proposed if a["action"] == "m365.revoke_sessions")
    reset = next(a for a in proposed if a["action"] == "m365.require_password_change")
    approved = client.post(f"{API}/response/actions/{revoke['id']}/approve", headers=admin).json()
    assert approved["status"] == "succeeded" and approved["decided_by"]["type"] == "user" and graph.user(user)["sessions_revoked"] == 1
    assert client.post(f"{API}/response/actions/{revoke['id']}/approve", headers=admin).status_code == 409
    rejected = client.post(f"{API}/response/actions/{reset['id']}/reject", json={"reason": "MFA is on"}, headers=admin).json()
    assert rejected["status"] == "rejected" and rejected["error"] == "MFA is on" and graph.user(user)["forceChange"] is False

    # Another alert in the same case does not run the playbook again.
    raise_alert(client, admin, "high", ["brute-force"], user=user)
    assert len(actions_of(client, admin, alert["case_id"])) == 2
    timeline = client.get(f"{API}/cases/{alert['case_id']}", headers=admin).json()["timeline"]
    kinds = [e["kind"] for e in timeline]
    assert kinds.count("playbook") == 1 and kinds.count("action") == 4  # 2 proposed, 1 ran, 1 not done


def test_automatic_only_when_the_organisation_allows_it(client, admin, graph):
    playbook = built_in(client, admin, "account-takeover")
    client.patch(f"{API}/playbooks/{playbook['id']}", json={"mode": "automatic"}, headers=admin)

    capped = raise_alert(client, admin, "critical", ["brute-force"], user=upn())
    assert {(a["status"], a["reason"]) for a in actions_of(client, admin, capped["case_id"])} == {("pending", "Your organisation's response mode is approval")}

    client.patch(f"{API}/response/settings", json={"mode": "automatic"}, headers=admin)
    user = upn()
    alert = raise_alert(client, admin, "critical", ["brute-force"], user=user)
    assert {a["status"] for a in actions_of(client, admin, alert["case_id"])} == {"succeeded"}
    assert graph.user(user)["sessions_revoked"] == 1 and graph.user(user)["forceChange"] is True

    # Beyond the hourly limit, actions wait for a person.
    client.patch(f"{API}/response/settings", json={"max_actions_per_hour": 2}, headers=admin)
    held = raise_alert(client, admin, "critical", ["brute-force"], user=upn())
    assert {a["status"] for a in actions_of(client, admin, held["case_id"])} == {"pending"}
    assert "in the last hour" in actions_of(client, admin, held["case_id"])[0]["reason"]


def test_protected_accounts_need_an_administrator(client, admin, analyst, graph):
    ceo = upn()
    client.patch(f"{API}/response/settings", json={"mode": "automatic", "protected_accounts": [ceo.upper(), " "]}, headers=admin)
    assert client.get(f"{API}/response/settings", headers=admin).json()["protected_accounts"] == [ceo]
    client.patch(f"{API}/playbooks/{built_in(client, admin, 'account-takeover')['id']}", json={"mode": "automatic"}, headers=admin)

    alert = raise_alert(client, admin, "critical", ["brute-force"], user=ceo)
    pending = actions_of(client, admin, alert["case_id"])
    assert {(a["status"], a["protected"]) for a in pending} == {("pending", True)}
    assert client.post(f"{API}/response/actions/{pending[0]['id']}/approve", headers=analyst).status_code == 403
    assert client.post(f"{API}/response/actions/{pending[0]['id']}/approve", headers=admin).json()["status"] == "succeeded"

    # An analyst acting on a protected account directly also waits for an administrator.
    asked = client.post(f"{API}/response/actions", json={"action": "m365.revoke_sessions", "target": {"type": "user", "value": ceo}}, headers=analyst).json()
    assert asked["status"] == "pending"
    # The organisation's UTDRS administrators are protected without being listed.
    me = client.get(f"{API}/auth/me", headers=admin).json()
    assert client.post(f"{API}/response/actions", json={"action": "m365.disable_account", "target": {"type": "user", "value": me["email"]}}, headers=analyst).json()["status"] == "pending"


def test_steps_without_their_connector_are_skipped(client, admin):
    alert = raise_alert(client, admin, "high", ["brute-force"], user=upn())
    assert actions_of(client, admin, alert["case_id"]) == []
    entry = next(e for e in client.get(f"{API}/cases/{alert['case_id']}", headers=admin).json()["timeline"] if e["kind"] == "playbook")
    assert "Microsoft 365 is not connected" in entry["text"]
    response = client.post(f"{API}/response/actions", json={"action": "m365.revoke_sessions", "target": {"type": "user", "value": upn()}}, headers=admin)
    assert response.status_code == 409 and response.json()["detail"] == "Microsoft 365 is not connected"


def test_removing_a_phishing_email_from_every_mailbox(client, admin, graph):
    message_id = f"<{uuid.uuid4().hex}@evil.example>"
    first, second, third = upn(), upn(), upn()
    for box, folder in ((first, "inbox"), (second, "junk")):
        graph.messages[(box, f"m-{uuid.uuid4().hex[:4]}")] = {"internetMessageId": message_id, "folder": folder}

    alert = raise_alert(client, admin, "medium", ["phishing"], internet_message_id=message_id, recipient=first)
    raise_alert(client, admin, "medium", ["phishing"], internet_message_id=message_id, recipient=second)
    raise_alert(client, admin, "medium", ["phishing"], internet_message_id=message_id, recipient=third)
    [purge] = actions_of(client, admin, alert["case_id"])
    assert purge["action"] == "m365.purge_message" and purge["target"] == {"type": "message", "value": message_id}

    # Approved after all three alerts, it reaches every recipient the case knows of by then.
    case = client.get(f"{API}/cases/{alert['case_id']}", headers=admin).json()
    assert {e["value"] for e in case["entities"] if e["type"] == "user"} == {first, second, third}
    client.post(f"{API}/response/actions/{purge['id']}/reject", headers=admin)
    ran = client.post(f"{API}/playbooks/{built_in(client, admin, 'phishing')['id']}/run", json={"case_id": alert["case_id"]}, headers=admin).json()
    [done] = ran["actions"]
    assert done["status"] == "succeeded" and done["result"]["moved"] == 2 and done["result"]["not_found"] == [third]
    assert {m["folder"] for m in graph.messages.values()} == {"recoverableitemsdeletions"}

    client.post(f"{API}/response/actions/{done['id']}/undo", headers=admin)
    assert sorted(m["folder"] for m in graph.messages.values()) == ["inbox", "junk"]


def test_removing_an_inbox_rule_keeps_it_to_put_back(client, admin, graph):
    user = upn()
    graph.rules[(user, "r1")] = {"id": "r1", "displayName": "fwd", "actions": {"forwardTo": [{"emailAddress": {"address": "x@evil.example"}}]}}
    action = client.post(f"{API}/response/actions", json={"action": "m365.remove_inbox_rule", "target": {"type": "user", "value": user}, "params": {"rule_id": "r1"}}, headers=admin).json()
    assert action["status"] == "succeeded" and not graph.rules
    client.post(f"{API}/response/actions/{action['id']}/undo", headers=admin)
    [(box, _)] = graph.rules
    restored = next(iter(graph.rules.values()))
    assert box == user and restored["displayName"] == "fwd" and "isReadOnly" not in restored

    missing = client.post(f"{API}/response/actions", json={"action": "m365.remove_inbox_rule", "target": {"type": "user", "value": user}, "params": {"rule_id": "nope"}}, headers=admin).json()
    assert missing["status"] == "failed" and "The rule was not found" in missing["error"]
    response = client.post(f"{API}/response/actions", json={"action": "m365.remove_inbox_rule", "target": {"type": "user", "value": user}}, headers=admin)
    assert response.status_code == 422 and "rule_id" in response.json()["detail"]


def test_running_a_playbook_yourself_and_undoing_it(client, admin):
    alert = raise_alert(client, admin, "high", ["ransomware"], hostname=f"fin-{uuid.uuid4().hex[:4]}")
    [proposed] = actions_of(client, admin, alert["case_id"])
    assert proposed["action"] == "utdrs.escalate_case" and proposed["status"] == "pending"

    approved = client.post(f"{API}/response/actions/{proposed['id']}/approve", headers=admin).json()
    assert approved["result"]["summary"] == "Priority raised from high to critical"
    assert client.get(f"{API}/cases/{alert['case_id']}", headers=admin).json()["priority"] == "critical"
    client.post(f"{API}/response/actions/{approved['id']}/undo", headers=admin)
    assert client.get(f"{API}/cases/{alert['case_id']}", headers=admin).json()["priority"] == "high"


def test_api_keys_ask_and_people_decide(client, admin):
    case_id = raise_alert(client, admin, "low", user=upn())["case_id"]
    body = client.post(f"{API}/api-keys/", json={"name": "soar", "scopes": ["response:read", "response:write"]}, headers=admin).json()
    key = {"Authorization": f"Bearer {body['key']}"}
    asked = client.post(f"{API}/response/actions", json={"action": "utdrs.escalate_case", "target": {"type": "case", "value": case_id}, "params": {"priority": "high"}}, headers=key).json()
    assert asked["status"] == "pending" and asked["reason"] == "Requested through an API key" and asked["requested_by"]["type"] == "api_key"
    assert client.post(f"{API}/response/actions/{asked['id']}/approve", headers=key).status_code == 403
    assert client.post(f"{API}/response/actions/{asked['id']}/approve", headers=admin).json()["status"] == "succeeded"

    other = client.post(f"{API}/api-keys/", json={"name": "cases-only", "scopes": ["cases:read"]}, headers=admin).json()["key"]
    assert client.get(f"{API}/response/actions", headers={"Authorization": f"Bearer {other}"}).status_code == 403
    assert client.get(f"{API}/playbooks/", headers={"Authorization": f"Bearer {other}"}).status_code == 403


def test_writing_playbooks(client, admin, analyst):
    step = {"action": "m365.revoke_sessions", "target": "user"}
    response = client.post(f"{API}/playbooks/", json={"name": "Impossible travel", "trigger": {"min_severity": "medium", "tags": ["impossible-travel"]}, "steps": [step]}, headers=admin)
    assert response.status_code == 201, response.text
    playbook = response.json()
    assert (playbook["mode"], playbook["enabled"], playbook["built_in"]) == ("approval", True, None)

    for bad in ({"action": "m365.nope", "target": "user"}, {"action": "m365.revoke_sessions", "target": "message"},
                {"action": "utdrs.escalate_case", "target": "case"}, {"action": "m365.restore_message", "target": "message"}):
        assert client.post(f"{API}/playbooks/", json={"name": "Bad", "steps": [bad]}, headers=admin).status_code == 422, bad
    assert client.post(f"{API}/playbooks/", json={"name": "x", "steps": [step]}, headers=analyst).status_code == 403
    assert client.patch(f"{API}/playbooks/{playbook['id']}", json={"enabled": False}, headers=analyst).status_code == 403

    assert client.patch(f"{API}/playbooks/{playbook['id']}", json={"enabled": False}, headers=admin).json()["enabled"] is False
    assert client.delete(f"{API}/playbooks/{playbook['id']}", headers=admin).status_code == 204
    response = client.delete(f"{API}/playbooks/{built_in(client, admin, 'phishing')['id']}", headers=admin)
    assert response.status_code == 409 and "turn it off" in response.json()["detail"]


def test_a_disabled_playbook_does_not_run(client, admin):
    client.patch(f"{API}/playbooks/{built_in(client, admin, 'ransomware')['id']}", json={"enabled": False}, headers=admin)
    alert = raise_alert(client, admin, "critical", ["ransomware"], hostname=f"ws-{uuid.uuid4().hex[:4]}")
    assert actions_of(client, admin, alert["case_id"]) == []


def test_response_is_kept_within_an_organisation(client, admin, monkeypatch):
    alert = raise_alert(client, admin, "high", ["ransomware"], hostname=f"ws-{uuid.uuid4().hex[:4]}")
    [action] = actions_of(client, admin, alert["case_id"])
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"org_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}

    assert client.get(f"{API}/response/actions/{action['id']}", headers=other).status_code == 404
    assert client.post(f"{API}/response/actions/{action['id']}/approve", headers=other).status_code == 404
    assert client.get(f"{API}/response/actions", headers=other).json() == []
    response = client.post(f"{API}/response/actions", json={"action": "utdrs.escalate_case", "target": {"type": "case", "value": alert["case_id"]}, "params": {"priority": "critical"}}, headers=other)
    assert response.status_code == 422 and response.json()["detail"] == "Case not found"
    # The other organisation has built-in playbooks of its own.
    theirs = client.get(f"{API}/playbooks/", headers=other).json()
    assert {p["built_in"] for p in theirs} == {"account-takeover", "phishing", "inbox-rule", "ransomware"}
    assert not {p["id"] for p in theirs} & {p["id"] for p in client.get(f"{API}/playbooks/", headers=admin).json()}
