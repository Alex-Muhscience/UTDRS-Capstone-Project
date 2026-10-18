"""The Microsoft 365 connector, against a stand-in for Microsoft serving Graph's documented formats."""
import base64
import json
import os
import secrets
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
SAMPLES = Path(__file__).parent.parent / "fixtures" / "m365"
AZURE_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
CLIENT_ID = "4a1b2c3d-0000-1111-2222-333344445555"
CLIENT_SECRET = "s3cr3t~value_from_entra"


def sample(name):
    return json.loads((SAMPLES / name).read_text())


class FakeMicrosoft:
    """Microsoft's sign-in service and Graph, serving the samples."""

    def __init__(self):
        self.calls = []
        self.issued = set()
        self.secrets = {CLIENT_ID: CLIENT_SECRET}
        self.forbidden = set()  # Graph paths answered 403
        self.throttle_once = set()
        self.revoked = []
        self.scopes = []
        self.subscribed = 0
        self.content_served = False
        self.management_forbidden = False
        self.rules = {}  # (mailbox, rule id) -> rule

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        self.calls.append((request.method, url.path, dict(url.params)))
        if url.host == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            if self.secrets.get(form["client_id"][0]) != form["client_secret"][0]:
                return httpx.Response(401, json={"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"})
            self.scopes.append(form["scope"][0])
            token = f"token-{uuid.uuid4().hex[:8]}"
            self.issued.add(token)
            return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": token})
        if request.headers.get("Authorization", "").removeprefix("Bearer ") not in self.issued:
            return httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken", "message": "Access token is empty."}})
        if url.host == "manage.office.com":
            return self.management(request)
        path = url.path.removeprefix("/v1.0")
        if path in self.forbidden:
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})
        if path in self.throttle_once:
            self.throttle_once.discard(path)
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"error": {"code": "TooManyRequests"}})
        if path == "/organization":
            return httpx.Response(200, json={"value": [{"id": AZURE_TENANT, "displayName": "Contoso"}]})
        if path == "/auditLogs/signIns":
            if url.params.get("$top") == "1":
                return httpx.Response(200, json={"value": []})
            return httpx.Response(200, json=sample("signins_page2.json" if "$skiptoken" in url.params else "signins_page1.json"))
        if path == "/auditLogs/directoryAudits":
            return httpx.Response(200, json=sample("directory_audits.json") if url.params.get("$top") != "1" else {"value": []})
        if path == "/security/alerts_v2":
            return httpx.Response(200, json=sample("alerts_v2.json") if url.params.get("$top") != "1" else {"value": []})
        if path == "/domains":
            return httpx.Response(200, json={"value": [{"id": "contoso.example", "isVerified": True}, {"id": "contoso-old.example", "isVerified": False}]})
        if path.endswith("/mailFolders/inbox/messageRules"):
            mailbox = path.split("/")[2]
            return httpx.Response(200, json={"value": [r for (box, _), r in self.rules.items() if box == mailbox]})
        if "/mailFolders/inbox/messageRules/" in path:
            mailbox, rule_id = path.split("/")[2], path.rsplit("/", 1)[1]
            if (mailbox, rule_id) not in self.rules:
                return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound", "message": "The rule was not found"}})
            if request.method == "DELETE":
                del self.rules[(mailbox, rule_id)]
                return httpx.Response(204)
            return httpx.Response(200, json=self.rules[(mailbox, rule_id)])
        if path.endswith("/revokeSignInSessions"):
            self.revoked.append(path.split("/")[2])
            return httpx.Response(200, json={"value": True})
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": path}})

    def management(self, request: httpx.Request) -> httpx.Response:
        """The Office 365 Management Activity API, serving the Exchange audit samples once."""
        if request.headers.get("Authorization", "").removeprefix("Bearer ") not in self.issued:
            return httpx.Response(401, json={"error": {"code": "AF10001", "message": "Invalid token"}})
        if self.management_forbidden:
            return httpx.Response(403, json={"error": {"code": "AF10002", "message": "Permission denied"}})
        path = request.url.path.split("/activity/feed", 1)[1]
        if path == "/subscriptions/start":
            self.subscribed += 1
            if self.subscribed > 1:
                return httpx.Response(400, json={"error": {"code": "AF20024", "message": "The subscription is already enabled."}})
            return httpx.Response(200, json={"contentType": "Audit.Exchange", "status": "enabled"})
        if path == "/subscriptions/list":
            return httpx.Response(200, json=[])
        if path == "/subscriptions/content":
            served, self.content_served = self.content_served, True
            return httpx.Response(200, json=[] if served else sample("exchange_content.json"))
        if path.startswith("/audit/"):
            return httpx.Response(200, json=sample("exchange_audit.json"))
        return httpx.Response(404, json={"error": {"code": "NotFound"}})


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def microsoft(monkeypatch):
    from core.services import m365

    fake = FakeMicrosoft()
    monkeypatch.setattr(m365, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    m365._tokens.clear()
    return fake


@pytest.fixture
def org(client, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"m365_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Org {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def connect(client, auth, secret=CLIENT_SECRET):
    """Connect, and wait for the first fetch that connecting starts."""
    from core.services import m365_ingest

    response = client.put(f"{API}/connectors/microsoft-365", json={"azure_tenant_id": AZURE_TENANT, "client_id": CLIENT_ID, "client_secret": secret}, headers=auth)
    client.portal.call(m365_ingest.idle)
    return response


def stored_connection(client):
    async def read():
        from core.database.connection import get_database

        return await get_database()["connections"].find_one({"client_id": CLIENT_ID}, sort=[("connected_at", -1)])

    return client.portal.call(read)


def test_connecting_with_an_app_registration(client, org, microsoft):
    status = client.get(f"{API}/connectors/microsoft-365", headers=org).json()
    assert status["connected"] is False and status["encryption_available"] is True
    assert {"name": "Mail.ReadWrite", "used_for": "remove phishing email from mailboxes and put it back"} in status["permissions"]

    wrong = connect(client, org, "wrong")
    assert wrong.status_code == 422 and wrong.json()["detail"] == "Microsoft refused to sign in (401): AADSTS7000215: Invalid client secret provided."

    response = connect(client, org)
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["connected"], body["mode"], body["status"], body["organisation_name"]) == (True, "own_app", "connected", "Contoso")
    assert all(check["ok"] for check in body["checks"]) and [c["name"] for c in body["checks"]][0] == "Signing in"
    assert "client_secret" not in body and CLIENT_SECRET not in response.text

    stored = stored_connection(client)
    assert stored["client_secret"].startswith("v1:") and CLIENT_SECRET not in stored["client_secret"]
    log = client.get(f"{API}/audit-log/", params={"action": "connectors"}, headers=org).json()
    assert log and CLIENT_SECRET not in json.dumps(log) and log[0]["details"]["request"]["client_secret"] == "[hidden]"

    # Its detection rules are in the catalogue, and the engine can run every one.
    rules = [r for r in client.get(f"{API}/detection/rules", params={"limit": 500}, headers=org).json() if r["name"].startswith("Microsoft 365:")]
    assert len(rules) == 9 and all(r["engine"]["runs"] for r in rules), [r["engine"] for r in rules]
    connect(client, org)  # connecting again adds them once
    assert len([r for r in client.get(f"{API}/detection/rules", params={"limit": 500}, headers=org).json() if r["name"].startswith("Microsoft 365:")]) == 9


def test_no_secret_is_stored_without_an_encryption_key(client, org, microsoft, monkeypatch):
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)
    response = connect(client, org)
    assert response.status_code == 409 and "ENCRYPTION_KEY" in response.json()["detail"]


def test_polling_brings_in_sign_ins_audits_and_defender_alerts(client, org, microsoft):
    connect(client, org)
    # Connecting fetches the last day straight away.
    first = client.get(f"{API}/connectors/microsoft-365", headers=org).json()
    assert (first["last_poll"], first["errors"]) == ({"signins": 3, "audits": 2, "alerts": 1, "mailbox": 3}, {})

    events = client.get(f"{API}/events/", params={"limit": 50}, headers=org).json()
    by_id = {e["raw_data"].get("external_id"): e for e in events}
    risky = by_id["signin:66ea54eb-6301-4ee5-be62-ff5a759b8100"]
    assert (risky["event_type"], risky["source"], risky["user_id"], risky["source_ip"]) == ("authentication", "m365", "jsmith@contoso.example", "203.0.113.45")
    assert risky["raw_data"]["risk_level"] == "high" and risky["raw_data"]["country"] == "NL" and risky["raw_data"]["status"] == "success"
    locked = by_id["signin:1f0d6a2e-4e5b-4a7c-9a1e-8b8c9d0e1f20"]
    assert locked["action"] == "failure" and locked["raw_data"]["error_code"] == 50053
    assert by_id["signin:9c3b2a10-7d6e-4f5a-8b9c-0d1e2f3a4b5c"]["raw_data"]["client_app"] == "Authenticated SMTP"  # from the second page
    role = by_id["audit:Directory_b8a2e5d4-1c3f-4a6b-9e0d-2f1c3b4a5d6e_ZA2GV_123456789"]
    assert (role["raw_data"]["activity"], role["raw_data"]["role"], role["raw_data"]["user"], role["raw_data"]["actor"]) == (
        "Add member to role", "Global Administrator", "backdoor@contoso.example", "jsmith@contoso.example")
    assert by_id["audit:Directory_c1d2e3f4-5a6b-7c8d-9e0f-1a2b3c4d5e6f_ZA2GV_987654321"]["raw_data"]["targets"] == ["Free PDF Converter"]

    # Microsoft's own alert is an alert in UTDRS, in a case about the person.
    [alert] = [a for a in client.get(f"{API}/alerts/", params={"limit": 50}, headers=org).json() if a["source"] == "microsoft-defender"]
    assert alert["title"] == "Email messages containing malicious URL removed after delivery" and alert["severity"] == "high"
    assert {"initialaccess", "microsoft-defender", "T1566.002"} <= set(alert["tags"])
    case = client.get(f"{API}/cases/{alert['case_id']}", headers=org).json()
    assert {"type": "user", "value": "ana@contoso.example", "name": None} in case["entities"]

    # Polling again brings nothing twice, and asks only for what is newer.
    again = client.post(f"{API}/connectors/microsoft-365/poll", headers=org).json()
    assert again["counts"] == {"signins": 0, "audits": 0, "alerts": 0, "mailbox": 0}
    last_signins = [params for method, path, params in microsoft.calls if path.endswith("/auditLogs/signIns") and "$filter" in params][-1]
    assert last_signins["$filter"] == "createdDateTime ge 2026-10-18T06:05:02Z" and last_signins["$orderby"] == "createdDateTime asc"
    status = client.get(f"{API}/connectors/microsoft-365", headers=org).json()
    assert status["last_poll"] == {"signins": 0, "audits": 0, "alerts": 0, "mailbox": 0} and status["last_poll_at"]


def test_a_missing_permission_stops_only_its_source(client, org, microsoft):
    microsoft.forbidden.add("/auditLogs/signIns")
    microsoft.throttle_once.add("/auditLogs/directoryAudits")  # Microsoft says to slow down once
    connect(client, org)
    result = client.get(f"{API}/connectors/microsoft-365", headers=org).json()
    assert result["last_poll"]["audits"] == 2 and result["last_poll"]["alerts"] == 1
    assert result["errors"] == {"signins": "Not allowed: check UTDRS's permissions in Microsoft 365"}
    assert result["status"] == "error"

    checks = {c["name"]: c for c in client.post(f"{API}/connectors/microsoft-365/check", headers=org).json()}
    assert checks["Sign-ins"] == {"name": "Sign-ins", "ok": False, "detail": "Not allowed: needs AuditLog.Read.All, and an Entra ID P1 or P2 licence"}
    assert checks["Defender alerts"]["ok"] is True


def test_response_actions_act_through_the_connection(client, org, microsoft):
    connect(client, org)
    types = {t["name"]: t for t in client.get(f"{API}/response/actions/types", headers=org).json()}
    assert types["m365.revoke_sessions"]["connected"] is True
    action = client.post(f"{API}/response/actions", json={"action": "m365.revoke_sessions", "target": {"type": "user", "value": "jsmith@contoso.example"}}, headers=org).json()
    assert action["status"] == "succeeded", action
    assert microsoft.revoked == ["jsmith@contoso.example"]


def test_connecting_by_admin_consent(client, org, microsoft, monkeypatch):
    monkeypatch.setattr(settings, "M365_CLIENT_ID", "utdrs-app-0000")
    monkeypatch.setattr(settings, "M365_CLIENT_SECRET", "utdrs-app-secret")
    microsoft.secrets["utdrs-app-0000"] = "utdrs-app-secret"
    url = client.post(f"{API}/connectors/microsoft-365/consent-url", json={"redirect_uri": "https://utdrs.example/connectors/microsoft-365/consented"}, headers=org).json()["url"]
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert parsed.path == "/organizations/v2.0/adminconsent" and query["client_id"] == ["utdrs-app-0000"]
    assert query["redirect_uri"] == ["https://utdrs.example/connectors/microsoft-365/consented"]
    state = query["state"][0]

    refused = client.post(f"{API}/connectors/microsoft-365/consent", json={"state": state, "error": "access_denied", "error_description": "The admin canceled the request."}, headers=org)
    assert refused.status_code == 422 and refused.json()["detail"] == "Consent was not given: The admin canceled the request."
    forged = client.post(f"{API}/connectors/microsoft-365/consent", json={"state": state + "x", "tenant": AZURE_TENANT, "admin_consent": "True"}, headers=org)
    assert forged.status_code == 422

    done = client.post(f"{API}/connectors/microsoft-365/consent", json={"state": state, "tenant": AZURE_TENANT, "admin_consent": "True"}, headers=org).json()
    from core.services import m365_ingest

    client.portal.call(m365_ingest.idle)
    assert (done["connected"], done["mode"], done["azure_tenant_id"], done["client_id"]) == (True, "consent", AZURE_TENANT, None)


def test_consent_started_by_one_organisation_cannot_finish_in_another(client, org, microsoft, monkeypatch):
    monkeypatch.setattr(settings, "M365_CLIENT_ID", "utdrs-app-0000")
    monkeypatch.setattr(settings, "M365_CLIENT_SECRET", "utdrs-app-secret")
    url = client.post(f"{API}/connectors/microsoft-365/consent-url", json={"redirect_uri": "https://utdrs.example/x"}, headers=org).json()["url"]
    state = parse_qs(urlparse(url).query)["state"][0]
    username, password = f"m365_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}
    response = client.post(f"{API}/connectors/microsoft-365/consent", json={"state": state, "tenant": AZURE_TENANT, "admin_consent": "True"}, headers=other)
    assert response.status_code == 422 and "someone else" in response.json()["detail"]


def test_without_consent_configured_only_an_own_app_is_offered(client, org, microsoft):
    assert client.get(f"{API}/connectors/microsoft-365", headers=org).json()["consent_available"] is False
    assert client.post(f"{API}/connectors/microsoft-365/consent-url", json={"redirect_uri": "https://x"}, headers=org).status_code == 409


def test_disconnecting_and_keeping_organisations_apart(client, org, microsoft):
    connect(client, org)
    username, password = f"m365_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": "Other"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}
    assert client.get(f"{API}/connectors/microsoft-365", headers=other).json()["connected"] is False
    assert client.get(f"{API}/response/actions/types", headers=other).json()[0]["connected"] is False

    assert client.delete(f"{API}/connectors/microsoft-365", headers=org).status_code == 204
    assert client.get(f"{API}/connectors/microsoft-365", headers=org).json()["connected"] is False
    assert client.delete(f"{API}/connectors/microsoft-365", headers=org).status_code == 404


def test_only_administrators_manage_connectors(client, org):
    username = f"ana_{uuid.uuid4().hex[:6]}"
    temporary = client.post(f"{API}/users/", json={"username": username, "email": f"{username}@example.com", "role": "analyst"}, headers=org).json()["temporary_password"]
    analyst = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': temporary}).json()['access_token']}"}
    assert client.get(f"{API}/connectors/microsoft-365", headers=analyst).status_code == 403
    assert connect(client, analyst).status_code == 403
