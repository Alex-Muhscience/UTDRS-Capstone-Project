"""Resetting a forgotten password and confirming an email address, by links sent by email."""
import os
import re
import secrets
import threading
import uuid

import pytest
from fastapi.testclient import TestClient

from config import settings
from tests.e2e.test_notifications import Mailbox, mail_to as notifications_to

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


def mail_to(mailbox, address):
    return notifications_to(mailbox, address, account_emails=True)


def deliver(client):
    from core.services import notifications

    client.portal.call(notifications.deliver_due)


def register(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"acct_{suffix}", "password": secrets.token_urlsafe(16)}
    address = f"acct_{suffix}@example.com"
    assert client.post(f"{API}/auth/register", json={**credentials, "email": address}).status_code == 200
    return credentials, address


def sign_in(client, credentials):
    return client.post(f"{API}/auth/login", data=credentials)


def link_in(mailbox, address, path):
    messages = mail_to(mailbox, address)
    assert messages, f"no email to {address}"
    text = messages[-1].get_content()
    match = re.search(rf"https://utdrs\.example{path}#token=([\w-]+)", text)
    assert match, text
    return match.group(1)


def test_a_forgotten_password_is_reset_from_an_email(client, mailbox):
    credentials, address = register(client)
    old_session = {"Authorization": f"Bearer {sign_in(client, credentials).json()['access_token']}"}

    response = client.post(f"{API}/auth/forgot-password", json={"login": address})
    assert response.status_code == 202
    deliver(client)
    token = link_in(mailbox, address, "/reset-password")
    assert mail_to(mailbox, address)[-1]["Subject"] == "[UTDRS] Reset your password"

    new_password = secrets.token_urlsafe(16)
    assert client.post(f"{API}/auth/reset-password", json={"token": token, "new_password": new_password}).status_code == 200
    assert sign_in(client, credentials).status_code == 401
    assert sign_in(client, {**credentials, "password": new_password}).status_code == 200
    # Everyone who knew the old password is signed out.
    assert client.get(f"{API}/auth/me", headers=old_session).status_code == 401
    # The link works once.
    again = client.post(f"{API}/auth/reset-password", json={"token": token, "new_password": secrets.token_urlsafe(16)})
    assert again.status_code == 400
    # Following it proved the address.
    me = sign_in(client, {**credentials, "password": new_password}).json()["user"]
    assert me["email_verified"] is True


def test_asking_never_says_whether_an_account_exists(client, mailbox):
    credentials, address = register(client)
    known = client.post(f"{API}/auth/forgot-password", json={"login": credentials["username"]})
    unknown = client.post(f"{API}/auth/forgot-password", json={"login": f"nobody_{uuid.uuid4().hex[:6]}@example.com"})
    assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())


def test_only_the_newest_link_works_and_requests_are_limited(client, mailbox):
    credentials, address = register(client)
    for _ in range(4):
        client.post(f"{API}/auth/forgot-password", json={"login": credentials["username"]})
    deliver(client)
    resets = [m for m in mail_to(mailbox, address) if m["Subject"] == "[UTDRS] Reset your password"]
    assert len(resets) == 3  # three an hour
    tokens = [re.search(r"#token=([\w-]+)", m.get_content()).group(1) for m in resets]
    assert client.post(f"{API}/auth/reset-password", json={"token": tokens[0], "new_password": secrets.token_urlsafe(16)}).status_code == 400
    assert client.post(f"{API}/auth/reset-password", json={"token": tokens[-1], "new_password": secrets.token_urlsafe(16)}).status_code == 200


def test_the_link_is_not_kept_after_it_is_sent(client, mailbox):
    credentials, address = register(client)
    client.post(f"{API}/auth/forgot-password", json={"login": address})
    deliver(client)

    async def stored():
        from core.database.connection import get_database

        return await get_database()["notifications"].find({"email": address, "kind": "account"}).to_list(10)

    kept = client.portal.call(stored)
    assert kept and all(n["status"] == "sent" and n["text"] is None for n in kept)


def test_registering_sends_a_link_to_confirm_the_address(client, mailbox):
    credentials, address = register(client)
    deliver(client)
    token = link_in(mailbox, address, "/verify-email")
    auth = {"Authorization": f"Bearer {sign_in(client, credentials).json()['access_token']}"}
    assert client.get(f"{API}/auth/me", headers=auth).json()["email_verified"] is False
    assert client.post(f"{API}/auth/verify-email", json={"token": token}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=auth).json()["email_verified"] is True

    # A new address has to be confirmed again.
    new_address = f"new_{uuid.uuid4().hex[:8]}@example.com"
    assert client.put(f"{API}/auth/me", json={"email": new_address}, headers=auth).json()["email_verified"] is False
    deliver(client)
    assert client.post(f"{API}/auth/verify-email", json={"token": link_in(mailbox, new_address, "/verify-email")}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=auth).json()["email_verified"] is True


def test_organisations_can_require_a_confirmed_address(client, mailbox, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_EMAIL_VERIFICATION", True)
    assert client.get(f"{API}/auth/config").json()["email_verification_required"] is True
    credentials, address = register(client)
    refused = sign_in(client, credentials)
    assert refused.status_code == 403
    assert refused.headers["X-Email-Verification-Required"] == "true"

    client.post(f"{API}/auth/resend-verification", json={"login": credentials["username"]})
    deliver(client)
    tokens = re.findall(r"#token=([\w-]+)", "".join(m.get_content() for m in mail_to(mailbox, address)))
    assert client.post(f"{API}/auth/verify-email", json={"token": tokens[0]}).status_code == 400  # replaced by the second
    assert client.post(f"{API}/auth/verify-email", json={"token": tokens[-1]}).status_code == 200
    assert sign_in(client, credentials).status_code == 200


def test_without_email_resetting_is_for_administrators(client, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", None)
    assert client.get(f"{API}/auth/config").json()["password_reset"] is False
    assert client.post(f"{API}/auth/forgot-password", json={"login": "anyone"}).status_code == 503
