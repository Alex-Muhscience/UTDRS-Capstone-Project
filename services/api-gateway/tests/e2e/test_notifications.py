"""Email notifications, delivered to a small SMTP server run by the test."""
import email
import email.policy
import os
import secrets
import socket
import socketserver
import threading
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


class Mailbox(socketserver.ThreadingTCPServer):
    """Just enough SMTP to receive mail: what arrives is kept in `received`; `refuse` makes it say no."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.received = []
        self.refuse = False
        super().__init__(("127.0.0.1", 0), SmtpSession)


class SmtpSession(socketserver.StreamRequestHandler):
    def reply(self, line: str) -> None:
        self.wfile.write(f"{line}\r\n".encode())

    def handle(self):
        self.reply("220 test ESMTP")
        recipients = []
        while line := self.rfile.readline():
            command = line.decode().strip().upper()
            if command.startswith(("EHLO", "HELO")):
                self.reply("250 test")
            elif command.startswith("MAIL FROM"):
                recipients = []
                self.reply("250 OK")
            elif command.startswith("RCPT TO"):
                recipients.append(line.decode().split(":", 1)[1].strip(" <>\r\n"))
                self.reply("250 OK")
            elif command == "DATA":
                self.reply("354 go on")
                data = b""
                while (chunk := self.rfile.readline()) != b".\r\n":
                    data += chunk
                if self.server.refuse:
                    self.reply("554 refused for the test")
                else:
                    self.server.received.append((recipients, email.message_from_bytes(data, policy=email.policy.default)))
                    self.reply("250 queued")
            elif command == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("250 OK")


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mailbox(monkeypatch):
    server = Mailbox()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(settings, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "SMTP_PORT", server.server_address[1])
    monkeypatch.setattr(settings, "SMTP_SECURITY", "none")
    monkeypatch.setattr(settings, "DASHBOARD_URL", "https://utdrs.example")
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def admin(client):
    response = client.post(f"{API}/auth/login", data={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def person(client, **preferences):
    """A new analyst with these notification preferences, and the email address they use."""
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"note_{suffix}", "password": secrets.token_urlsafe(16)}
    address = f"note_{suffix}@example.com"
    client.post(f"{API}/auth/register", json={**credentials, "email": address})
    auth = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    if preferences:
        assert client.patch(f"{API}/notifications/preferences", json=preferences, headers=auth).status_code == 200
    return auth, address


@pytest.fixture(autouse=True)
def quiet_everyone_else(client, admin):
    """People from other tests keep the defaults; this test's people opt in to what it checks."""
    yield
    from core.services import playbooks

    client.portal.call(playbooks.idle)


def deliver(client):
    from core.services import notifications, playbooks

    client.portal.call(playbooks.idle)
    client.portal.call(notifications.deliver_due)


def mail_to(mailbox, address):
    return [message for recipients, message in mailbox.received if address in recipients]


def raise_alert(client, auth, severity="high", tags=(), **raw):
    event = client.post(
        f"{API}/events/",
        json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "edr", "description": "x", "raw_data": raw},
        headers=auth,
    ).json()
    return client.post(
        f"{API}/alerts/",
        json={"title": f"Shadow copies deleted {uuid.uuid4().hex[:4]}", "description": "x", "severity": severity, "source": "core-engine",
              "type": "signature", "tags": list(tags), "event_ids": [event["id"]]},
        headers=auth,
    ).json()


def test_preferences_have_safe_defaults_and_can_change(client, mailbox):
    auth, address = person(client)
    prefs = client.get(f"{API}/notifications/preferences", headers=auth).json()
    assert prefs == {"email": True, "new_cases": "high", "approvals": True, "actions": "failed", "reports": True, "email_configured": True, "address": address}
    changed = client.patch(f"{API}/notifications/preferences", json={"new_cases": "off", "actions": "all"}, headers=auth).json()
    assert (changed["new_cases"], changed["actions"], changed["approvals"]) == ("off", "all", True)
    assert client.patch(f"{API}/notifications/preferences", json={"new_cases": "sometimes"}, headers=auth).status_code == 422


def test_a_new_case_is_emailed_to_those_who_want_it(client, admin, mailbox):
    keen, keen_address = person(client, new_cases="medium")
    _, quiet_address = person(client, new_cases="off")
    _, critical_only = person(client, new_cases="critical")
    host = f"fin-{uuid.uuid4().hex[:4]}"
    alert = raise_alert(client, admin, "high", ["ransomware"], hostname=host)
    deliver(client)

    [message] = [m for m in mail_to(mailbox, keen_address) if host in m["Subject"]]
    assert message["Subject"].startswith("[UTDRS] High case: Shadow copies deleted") and message["From"] == settings.MAIL_FROM
    body = message.get_payload(decode=True).decode()
    assert host in body and "Disconnect the affected computer from the network now" in body
    case_id = client.get(f"{API}/alerts/{alert['id']}", headers=admin).json()["case_id"]
    assert f"https://utdrs.example/cases/{case_id}" in body
    assert not [m for m in mail_to(mailbox, quiet_address) + mail_to(mailbox, critical_only) if host in m["Subject"]]

    # A second alert in the same case is not a new case.
    raise_alert(client, admin, "critical", hostname=host)
    deliver(client)
    assert len([m for m in mail_to(mailbox, keen_address) if host in m["Subject"]]) == 1

    log = client.get(f"{API}/notifications/", params={"status": "sent"}, headers=admin).json()
    assert any(n["email"] == keen_address and n["kind"] == "case_opened" and n["about"] == {"type": "case", "id": case_id} for n in log)


def test_approvals_needed_and_actions_done(client, admin, mailbox):
    _, approver = person(client, new_cases="off", approvals=True, actions="all")
    _, uninterested = person(client, new_cases="off", approvals=False, actions="off")
    host = f"ws-{uuid.uuid4().hex[:4]}"
    alert = raise_alert(client, admin, "high", ["ransomware"], hostname=host)
    deliver(client)

    [asked] = [m for m in mail_to(mailbox, approver) if m["Subject"].startswith("[UTDRS] Approval needed")]
    assert asked["Subject"] == "[UTDRS] Approval needed: Raise the case's priority — the case"
    assert 'Playbook "Ransomware" asks to: Raise the case\'s priority' in asked.get_payload(decode=True).decode()
    assert not mail_to(mailbox, uninterested)

    case_id = client.get(f"{API}/alerts/{alert['id']}", headers=admin).json()["case_id"]
    [action] = client.get(f"{API}/response/actions", params={"case_id": case_id}, headers=admin).json()
    client.post(f"{API}/response/actions/{action['id']}/approve", headers=admin)
    deliver(client)
    done = [m for m in mail_to(mailbox, approver) if m["Subject"].startswith("[UTDRS] Done")]
    assert done and "Priority raised from high to critical" in done[-1].get_payload(decode=True).decode()


def test_failures_are_retried_and_then_given_up(client, admin, mailbox):
    from core.database.connection import get_database
    from core.services import notifications

    _, address = person(client, new_cases="info")
    mailbox.refuse = True
    raise_alert(client, admin, "low", user=f"retry-{uuid.uuid4().hex[:4]}")
    deliver(client)

    async def mine():
        return await get_database()["notifications"].find_one({"email": address})

    first = client.portal.call(mine)
    assert first["status"] == "queued" and first["attempts"] == 1 and "554 refused for the test" in first["error"]
    assert first["next_attempt_at"] > datetime.now(timezone.utc)  # waits before retrying

    async def due_now():
        await get_database()["notifications"].update_one({"_id": first["_id"]}, {"$set": {"next_attempt_at": datetime.now(timezone.utc)}})

    mailbox.refuse = False
    client.portal.call(due_now)
    deliver(client)
    assert client.portal.call(mine)["status"] == "sent" and mail_to(mailbox, address)

    # One that never gets through is given up after the last attempt.
    mailbox.refuse = True
    raise_alert(client, admin, "low", user=f"never-{uuid.uuid4().hex[:4]}")
    for _ in range(notifications.MAX_ATTEMPTS):
        async def all_due():
            await get_database()["notifications"].update_many({"email": address, "status": "queued"}, {"$set": {"next_attempt_at": datetime.now(timezone.utc)}})

        client.portal.call(all_due)
        deliver(client)

    async def last():
        return await get_database()["notifications"].find_one({"email": address}, sort=[("created_at", -1)])

    gave_up = client.portal.call(last)
    assert gave_up["status"] == "failed" and gave_up["attempts"] == notifications.MAX_ATTEMPTS


def test_nobody_is_flooded(client, admin, mailbox, monkeypatch):
    monkeypatch.setattr(settings, "NOTIFY_MAX_PER_USER_PER_HOUR", 2)
    _, address = person(client, new_cases="info")
    for _ in range(3):
        raise_alert(client, admin, "low", user=f"flood-{uuid.uuid4().hex[:4]}")
    deliver(client)
    log = [n for n in client.get(f"{API}/notifications/", params={"limit": 500}, headers=admin).json() if n["email"] == address]
    assert sorted(n["status"] for n in log) == ["sent", "sent", "skipped"]
    assert "More than 2 emails to this person in an hour" in next(n["error"] for n in log if n["status"] == "skipped")


def test_without_email_configured_nothing_is_sent_and_the_log_says_why(client, admin):
    _, address = person(client, new_cases="info")
    raise_alert(client, admin, "low", user=f"nomail-{uuid.uuid4().hex[:4]}")
    log = [n for n in client.get(f"{API}/notifications/", headers=admin).json() if n["email"] == address]
    assert [(n["status"], n["error"]) for n in log] == [("skipped", "Email is not configured (SMTP_HOST)")]


def test_a_title_cannot_add_headers(client, admin, mailbox):
    _, address = person(client, new_cases="info")
    event = client.post(f"{API}/events/", json={"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process", "source": "x",
                                                "description": "x", "raw_data": {"user": f"inj-{uuid.uuid4().hex[:4]}"}}, headers=admin).json()
    client.post(f"{API}/alerts/", json={"title": "Odd\r\nBcc: attacker@evil.example", "description": "x", "severity": "low", "source": "x",
                                        "type": "x", "event_ids": [event["id"]]}, headers=admin)
    deliver(client)
    [message] = [m for m in mail_to(mailbox, address) if "Odd" in m["Subject"]]
    assert message["Bcc"] is None and "Bcc: attacker@evil.example" in message["Subject"]
    assert all("attacker@evil.example" not in recipients for recipients, _ in mailbox.received)


def test_a_test_email(client, mailbox):
    auth, address = person(client)
    assert client.post(f"{API}/notifications/test", headers=auth).json() == {"sent": True, "error": None}
    assert mail_to(mailbox, address)[0]["Subject"] == "[UTDRS] Test email"


def test_a_test_email_says_what_went_wrong(client, monkeypatch):
    auth, _ = person(client)
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    monkeypatch.setattr(settings, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "SMTP_PORT", port)
    monkeypatch.setattr(settings, "SMTP_SECURITY", "none")
    result = client.post(f"{API}/notifications/test", headers=auth).json()
    assert result["sent"] is False and "ConnectionRefusedError" in result["error"]


def test_the_log_is_for_administrators_and_api_keys_have_no_inbox(client, admin):
    auth, _ = person(client)
    assert client.get(f"{API}/notifications/", headers=auth).status_code == 403
    key = client.post(f"{API}/api-keys/", json={"name": "n", "scopes": ["alerts:read"]}, headers=admin).json()["key"]
    assert client.get(f"{API}/notifications/preferences", headers={"Authorization": f"Bearer {key}"}).status_code == 403
