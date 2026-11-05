"""The Google Workspace connector, against a stand-in for Google's APIs."""
import base64
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


def now_iso(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Google:
    """Google's token endpoint (checking the service account's signed JWT), Reports API and Directory API."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.client_email = f"utdrs@project-{uuid.uuid4().hex[:6]}.iam.gserviceaccount.com"
        self.delegated = True
        self.activities = {"login": [], "admin": [], "token": [], "user_accounts": [], "drive": []}
        self.users = {}
        self.calls = []

    def key_json(self):
        pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        return json.dumps({"type": "service_account", "client_email": self.client_email, "client_id": "1234567890",
                           "private_key": pem, "token_uri": "https://oauth2.googleapis.com/token"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        query = request.url.query.decode() if isinstance(request.url.query, bytes) else request.url.query
        self.calls.append(f"{request.method} {request.url.path}" + (f"?{query}" if query else ""))
        if request.url.host == "oauth2.googleapis.com":
            assertion = parse_qs(request.content.decode())["assertion"][0]
            claims = jwt.decode(assertion, self.key.public_key(), algorithms=["RS256"], audience="https://oauth2.googleapis.com/token")
            assert claims["iss"] == self.client_email and "admin.reports.audit.readonly" in claims["scope"]
            if not self.delegated:
                return httpx.Response(401, json={"error": "unauthorized_client", "error_description": "Client is unauthorized"})
            return httpx.Response(200, json={"access_token": "ya29.token", "expires_in": 3600, "token_type": "Bearer"})
        assert request.headers["authorization"] == "Bearer ya29.token"
        path = request.url.path
        if "/admin/reports/v1/activity/users/all/applications/" in path:
            items = self.activities[path.rsplit("/", 1)[1]]
            wanted = request.url.params.get("eventName")
            if wanted:
                items = [a for a in items if any(e["name"] == wanted for e in a["events"])]
            return httpx.Response(200, json={"items": items})
        if path.startswith("/admin/directory/v1/users/"):
            email = path.split("/users/", 1)[1]
            if path.endswith("/signOut"):
                return httpx.Response(204)
            user = self.users.setdefault(email.split("/")[0], {"isAdmin": False, "suspended": False})
            if request.method == "PUT":
                user.update(json.loads(request.content))
            return httpx.Response(200, json=user)
        return httpx.Response(404, json={"error": {"message": "not found"}})


def activity(application, name, actor, parameters=(), address="198.51.100.7", minutes_ago=5):
    return {"id": {"time": now_iso(minutes_ago), "uniqueQualifier": str(uuid.uuid4().int)[:18], "applicationName": application},
            "actor": {"email": actor}, "ipAddress": address,
            "events": [{"type": "x", "name": name, "parameters": [{"name": k, **v} for k, v in parameters]}]}


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def google(monkeypatch):
    from core.services import google_workspace

    fake = Google()
    monkeypatch.setattr(google_workspace, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    google_workspace._tokens.clear()
    return fake


@pytest.fixture
def admin(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"gw_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"gw_{suffix}@example.com", "organisation": f"Org {suffix}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}


def connect(client, admin, google):
    from core.services import google_workspace

    response = client.put(f"{API}/connectors/google-workspace", json={"service_account_key": google.key_json(), "admin_email": "it@contoso.com"}, headers=admin)
    client.portal.call(google_workspace.idle)
    return response


def test_connecting_checks_the_key_and_keeps_it_secret(client, admin, google):
    google.delegated = False
    refused = connect(client, admin, google)
    assert refused.status_code == 422 and "domain-wide delegation" in refused.json()["detail"]
    google.delegated = True
    bad = client.put(f"{API}/connectors/google-workspace", json={"service_account_key": '{"type": "authorized_user"}', "admin_email": "it@contoso.com"}, headers=admin)
    assert bad.status_code == 422

    connected = connect(client, admin, google)
    assert connected.status_code == 200, connected.text
    body = connected.json()
    assert body["connected"] and body["domain"] == "contoso.com" and body["client_id"] == "1234567890"
    assert "key" not in body and "private_key" not in json.dumps(body)
    rules = client.get(f"{API}/detection/rules", params={"limit": 500}, headers=admin).json()
    assert sum(r["name"].startswith("Google Workspace:") for r in rules) == 9


def test_activities_become_events_once_and_raise_alerts(client, admin, google, monkeypatch):
    google.activities["login"] = [
        activity("login", "login_failure", "ann@contoso.com", [("login_failure_type", {"value": "login_failure_invalid_password"})]),
        activity("login", "login_success", "ann@contoso.com"),
        activity("login", "suspicious_login", "bo@contoso.com"),
    ]
    google.activities["admin"] = [activity("admin", "ASSIGN_ROLE", "it@contoso.com", [("USER_EMAIL", {"value": "bo@contoso.com"}), ("ROLE_NAME", {"value": "_SEED_ADMIN_ROLE"})])]
    google.activities["token"] = [activity("token", "authorize", "cy@contoso.com", [("app_name", {"value": "Mail Helper"}),
                                                                                      ("scope", {"multiValue": ["https://mail.google.com/"]})])]
    google.activities["user_accounts"] = [activity("user_accounts", "email_forwarding_out_of_domain", "bo@contoso.com")]
    google.activities["drive"] = [
        activity("drive", "change_user_access", "ann@contoso.com", [("doc_title", {"value": "Payroll 2026"}), ("visibility_change", {"value": "external"}),
                                                                   ("target_user", {"value": "someone@gmail.com"}), ("primary_event", {"boolValue": True})]),
        # A secondary event of the same action: not kept.
        activity("drive", "change_user_access", "ann@contoso.com", [("doc_title", {"value": "Payroll 2026"}), ("primary_event", {"boolValue": False})]),
        # Views are never asked for.
        activity("drive", "view", "ann@contoso.com", [("doc_title", {"value": "Notes"})]),
    ]
    connect(client, admin, google)
    status = client.get(f"{API}/connectors/google-workspace", headers=admin).json()
    assert status["last_poll"] == {"login": 3, "admin": 1, "token": 1, "user_accounts": 1, "drive": 1} and status["errors"] == {}
    drive_calls = [call for call in google.calls if "/applications/drive" in call]
    assert drive_calls and all("eventName=change_" in call for call in drive_calls)

    events = client.get(f"{API}/events/", params={"limit": 50}, headers=admin).json()
    google_events = [e for e in events if e["source"] == "google"]
    assert len(google_events) == 7
    shared = next(e for e in google_events if e["event_type"] == "file_sharing")
    assert shared["raw_data"]["visibility_change"] == "external" and "outside your organisation" in shared["description"]
    failure = next(e for e in google_events if e["raw_data"]["activity"] == "login_failure")
    assert failure["event_type"] == "authentication" and failure["raw_data"]["status"] == "failure" and failure["raw_data"]["user"] == "ann@contoso.com"

    # The next poll overlaps the last: nothing is stored twice.
    assert client.post(f"{API}/connectors/google-workspace/poll", headers=admin).json()["counts"] == {"login": 0, "admin": 0, "token": 0, "user_accounts": 0, "drive": 0}


def test_rules_match_what_google_reports(client, admin, google):
    """Each built-in rule matches the activity it is about, by the same logic the engine runs."""
    from core.services import google_workspace, rule_tests

    examples = {
        "Google Workspace: suspicious sign-in": activity("login", "suspicious_login", "a@contoso.com"),
        "Google Workspace: government-backed attack warning": activity("login", "gov_attack_warning", "a@contoso.com"),
        "Google Workspace: account disabled as hijacked": activity("login", "account_disabled_hijacked", "a@contoso.com"),
        "Google Workspace: 2-step verification turned off": activity("login", "2sv_disable", "a@contoso.com"),
        "Google Workspace: administrator privileges granted": activity("admin", "ASSIGN_ROLE", "a@contoso.com"),
        "Google Workspace: app given access to mail or files": activity("token", "authorize", "a@contoso.com", [("scope", {"multiValue": ["https://www.googleapis.com/auth/drive"]})]),
        "Google Workspace: file shared outside": activity("drive", "change_user_access", "a@contoso.com", [("visibility_change", {"value": "external"})]),
        "Google Workspace: file made public on the web": activity("drive", "change_document_visibility", "a@contoso.com",
                                                                  [("new_value", {"value": "public_on_the_web"}), ("old_value", {"value": "private"})]),
        "Google Workspace: mail forwarded outside": activity("user_accounts", "email_forwarding_out_of_domain", "a@contoso.com"),
    }
    for rule in google_workspace.RULES:
        record = examples[rule["name"]]
        [event] = google_workspace.activity_events(record["id"]["applicationName"], record)
        case = {"name": rule["name"], "event": {**event.model_dump(mode="json"), "data": event.raw_data}}
        assert rule_tests.run(rule["logic"], [case])["passed"], rule["name"]
        benign = {"name": "benign", "event": {"event_type": "authentication", "source": "google", "activity": "login_success"}, "expect": "no_match"}
        assert rule_tests.run(rule["logic"], [benign])["passed"], rule["name"]


def test_response_actions_act_on_google_accounts(client, admin, google):
    connect(client, admin, google)
    types = {t["name"] for t in client.get(f"{API}/response/actions/types", headers=admin).json()}
    # Restoring is offered on its own too, as enabling a Microsoft 365 account is.
    assert {"google.sign_out", "google.suspend_user", "google.unsuspend_user"} <= types

    suspended = client.post(f"{API}/response/actions", json={"action": "google.suspend_user", "target": {"type": "user", "value": "bo@contoso.com"}}, headers=admin).json()
    assert suspended["status"] == "succeeded", suspended
    assert google.users["bo@contoso.com"]["suspended"] is True
    undone = client.post(f"{API}/response/actions/{suspended['id']}/undo", headers=admin)
    assert undone.status_code == 200, undone.text
    assert google.users["bo@contoso.com"]["suspended"] is False

    google.users["root@contoso.com"] = {"isAdmin": True, "suspended": False}
    refused = client.post(f"{API}/response/actions", json={"action": "google.suspend_user", "target": {"type": "user", "value": "root@contoso.com"}}, headers=admin).json()
    assert refused["status"] in ("refused", "failed") and google.users["root@contoso.com"]["suspended"] is False

    signed_out = client.post(f"{API}/response/actions", json={"action": "google.sign_out", "target": {"type": "user", "value": "ann@contoso.com"}}, headers=admin).json()
    assert signed_out["status"] == "succeeded" and "POST /admin/directory/v1/users/ann@contoso.com/signOut" in google.calls


def test_disconnecting_forgets_the_key(client, admin, google):
    connect(client, admin, google)
    assert client.delete(f"{API}/connectors/google-workspace", headers=admin).status_code == 204
    assert client.get(f"{API}/connectors/google-workspace", headers=admin).json()["connected"] is False
