"""Onboarding: the checklist follows the organisation's real state."""
import base64
import os
import secrets
import uuid

import httpx
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
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    username, password = f"onb_{uuid.uuid4().hex[:6]}", secrets.token_urlsafe(16)
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": password, "organisation": f"Acme {username}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': password}).json()['access_token']}"}


def steps(client, auth):
    body = client.get(f"{API}/onboarding/", headers=auth).json()
    return body, {s["key"]: s for s in body["steps"]}


def test_a_new_organisation_starts_with_what_is_left(client, org):
    body, by = steps(client, org)
    assert [s["key"] for s in body["steps"]] == ["name", "microsoft_365", "response", "team", "email", "results"]
    assert by["name"]["done"] is True and by["name"]["detail"].startswith("Called Acme")  # named when registering
    assert not any(by[k]["done"] for k in ("microsoft_365", "response", "team", "email", "results"))
    assert by["team"]["optional"] and by["email"]["optional"] and not by["microsoft_365"]["optional"]
    assert by["email"]["detail"] == "Email is not set up on this UTDRS yet (SMTP settings)"
    assert (body["done"], body["total"], body["complete"], body["dismissed"]) == (1, 6, False, False)


def test_steps_are_done_wherever_they_are_done(client, org, monkeypatch):
    client.patch(f"{API}/response/settings", json={"mode": "notify"}, headers=org)
    username = f"ana_{uuid.uuid4().hex[:6]}"
    client.post(f"{API}/users/", json={"username": username, "email": f"{username}@example.com", "role": "analyst"}, headers=org)
    client.post(f"{API}/events/", json={"timestamp": "2026-10-18T06:00:00Z", "event_type": "process", "source": "edr", "description": "x"}, headers=org)
    _, by = steps(client, org)
    assert by["response"]["done"] and by["response"]["detail"] == "Playbooks only suggest"
    assert by["team"]["done"] and by["team"]["detail"] == "2 people"
    assert by["results"]["done"] and by["results"]["detail"].startswith("1 events in the last day")


def test_connecting_microsoft_365_brings_first_results_in_minutes(client, org, monkeypatch):
    from core.services import m365, m365_ingest
    from tests.e2e.test_m365 import AZURE_TENANT, CLIENT_ID, CLIENT_SECRET, FakeMicrosoft

    fake = FakeMicrosoft()
    monkeypatch.setattr(m365, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode())
    client.put(f"{API}/connectors/microsoft-365", json={"azure_tenant_id": AZURE_TENANT, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}, headers=org)
    client.portal.call(m365_ingest.idle)

    body, by = steps(client, org)
    assert by["microsoft_365"]["done"] and by["microsoft_365"]["detail"] == "Connected to Contoso"
    assert body["results"]["sign_ins"] == 3 and body["results"]["alerts"] >= 1 and by["results"]["done"]
    client.delete(f"{API}/connectors/microsoft-365", headers=org)
    assert steps(client, org)[1]["microsoft_365"]["done"] is False  # undone, shown again


def test_a_test_email_that_arrives_ticks_email(client, org, monkeypatch):
    from core.services import notifications

    async def delivered(to, subject, text):
        return None

    monkeypatch.setattr(settings, "SMTP_HOST", "mail.example")
    monkeypatch.setattr(notifications, "send_email", delivered)
    assert client.post(f"{API}/notifications/test", headers=org).json()["sent"] is True
    assert steps(client, org)[1]["email"] == {"key": "email", "title": "Check email works", "done": True, "detail": "A test email arrived", "optional": True, "attention": False}


def test_only_administrators_put_the_checklist_away(client, org):
    username = f"ana_{uuid.uuid4().hex[:6]}"
    temporary = client.post(f"{API}/users/", json={"username": username, "email": f"{username}@example.com", "role": "analyst"}, headers=org).json()["temporary_password"]
    analyst = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': username, 'password': temporary}).json()['access_token']}"}
    assert client.get(f"{API}/onboarding/", headers=analyst).status_code == 200
    assert client.patch(f"{API}/onboarding/", json={"dismissed": True}, headers=analyst).status_code == 403
    assert client.patch(f"{API}/onboarding/", json={"dismissed": True}, headers=org).json()["dismissed"] is True
    assert client.patch(f"{API}/onboarding/", json={"dismissed": False}, headers=org).json()["dismissed"] is False


def test_the_default_organisation_is_asked_for_a_name(client):
    admin = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': os.environ['ADMIN_USERNAME'], 'password': os.environ['ADMIN_PASSWORD']}).json()['access_token']}"}
    by = steps(client, admin)[1]
    assert by["name"]["done"] is (client.get(f"{API}/tenants/current", headers=admin).json()["name"] != settings.DEFAULT_TENANT_NAME)
