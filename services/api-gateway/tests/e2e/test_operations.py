"""Running UTDRS: metrics, readiness, heartbeats, and alerts about the platform's own health."""
import os
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings
from core.services import core_engine_client
from core.services.core_engine_client import CoreEngineClient
from tests.e2e.test_notifications import Mailbox

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def run(client, function, *args):
    return client.portal.call(function, *args)


def db_call(client, work):
    from core.database.connection import get_database

    async def call():
        return await work(get_database())

    return run(client, call)


@pytest.fixture
def mailbox(monkeypatch):
    server = Mailbox()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(settings, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "SMTP_PORT", server.server_address[1])
    monkeypatch.setattr(settings, "SMTP_SECURITY", "none")
    monkeypatch.setattr(settings, "OPERATOR_EMAILS", ["ops@example.com"])
    monkeypatch.setattr(settings, "HEALTH_ALERT_AFTER_MINUTES", 0)
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def fresh_health_state(client):
    db_call(client, lambda db: db["health_checks"].delete_many({}))
    yield


def to_ops(mailbox):
    return [m for recipients, m in mailbox.received if "ops@example.com" in recipients]


# ---------------------------------------------------------------------------- Metrics

def test_metrics_need_their_token(client, monkeypatch):
    monkeypatch.setattr(settings, "METRICS_TOKEN", None)
    assert client.get(f"{API}/metrics").status_code == 404
    monkeypatch.setattr(settings, "METRICS_TOKEN", "scrape-secret")
    assert client.get(f"{API}/metrics").status_code == 401
    assert client.get(f"{API}/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(f"{API}/metrics", headers={"Authorization": "Bearer scrape-secret"}).status_code == 200


def test_metrics_count_requests_by_route_template(client, monkeypatch):
    monkeypatch.setattr(settings, "METRICS_TOKEN", "scrape-secret")
    for _ in range(3):
        client.get(f"{API}/health")
    client.get(f"{API}/alerts/665f1c2ab1e2c3d4e5f60aaa")  # 401: no token; counted under its template
    text = client.get(f"{API}/metrics", headers={"Authorization": "Bearer scrape-secret"}).text

    def value(prefix):
        line = next(line for line in text.splitlines() if line.startswith(prefix))
        return float(line.rsplit(" ", 1)[1])

    assert value('utdrs_http_requests_total{method="GET",route="/api/v1/health",status="2xx"}') >= 3
    assert value('utdrs_http_requests_total{method="GET",route="/api/v1/alerts/{alert_id}",status="4xx"}') >= 1
    assert "665f1c2ab1e2c3d4e5f60aaa" not in text  # never an actual path
    assert value('utdrs_http_request_duration_seconds_count{method="GET",route="/api/v1/health"}') >= 3
    for name in ("utdrs_database_ping_seconds", "utdrs_core_engine_reachable", "utdrs_analysis_waiting", "utdrs_email_outbox",
                 "utdrs_webhook_deliveries", "utdrs_organisations", "utdrs_sessions_active"):
        assert f"# TYPE {name} " in text


def test_totals_are_shared_by_every_process(client, monkeypatch):
    """Counts reach the database, so a scrape answered by another process reports them too."""
    from core.services import metrics

    metrics.record("GET", "/api/v1/shared-test", 200, 0.2)
    run(client, metrics.flush)
    stored = db_call(client, lambda db: db["metrics_http"].find_one({"_id": "GET /api/v1/shared-test 2xx"}))
    assert stored["count"] >= 1 and stored["le_2"] >= 1  # within 0.25 s


# ---------------------------------------------------------------------------- Readiness and heartbeats

def test_readiness_reports_problems_but_still_serves(client):
    ready = client.get(f"{API}/health/ready")
    assert ready.status_code == 200
    assert ready.json()["database"] == "connected"


def test_a_loop_that_stops_is_noticed(client, mailbox):
    from core.services import heartbeat, platform_health

    run(client, heartbeat.beat, "test_loop", 60)
    loops = {loop["_id"]: loop for loop in run(client, heartbeat.all_loops)}
    assert loops["test_loop"]["stale"] is False

    db_call(client, lambda db: db["heartbeats"].update_one({"_id": "test_loop"}, {"$set": {"at": datetime.now(timezone.utc) - timedelta(hours=1)}}))
    run(client, platform_health.check_once)
    assert any("test_loop" in m["Subject"] for m in to_ops(mailbox))
    assert "loop:test_loop" in client.get(f"{API}/health/ready").json()["problems"]
    db_call(client, lambda db: db["heartbeats"].delete_one({"_id": "test_loop"}))


# ---------------------------------------------------------------------------- Platform alerts

def test_operators_hear_once_when_the_engine_is_down_and_when_it_is_back(client, mailbox, monkeypatch):
    from core.services import platform_health

    up = {"ok": False}

    def handler(request):
        return httpx.Response(200 if up["ok"] else 503, json={})

    monkeypatch.setattr(core_engine_client, "get_core_engine_client",
                        lambda: CoreEngineClient("http://core-engine", transport=httpx.MockTransport(handler)))
    run(client, platform_health.check_once)
    run(client, platform_health.check_once)
    problems = [m for m in to_ops(mailbox) if m["Subject"] == "[UTDRS] Problem: core_engine"]
    assert len(problems) == 1  # once, however many rounds it lasts
    assert "does not answer" in problems[0].get_content()

    up["ok"] = True
    run(client, platform_health.check_once)
    assert [m["Subject"] for m in to_ops(mailbox)].count("[UTDRS] Resolved: core_engine") == 1


def test_a_short_blip_is_not_reported(client, mailbox, monkeypatch):
    from core.services import platform_health

    monkeypatch.setattr(settings, "HEALTH_ALERT_AFTER_MINUTES", 5)
    monkeypatch.setattr(core_engine_client, "get_core_engine_client",
                        lambda: CoreEngineClient("http://core-engine", transport=httpx.MockTransport(lambda r: httpx.Response(503))))
    run(client, platform_health.check_once)
    assert not to_ops(mailbox)


# ---------------------------------------------------------------------------- Connector health

@pytest.fixture
def organisation(client, monkeypatch):
    """A new organisation with a Microsoft 365 connection; its administrator's email."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"ops_{suffix}", "password": secrets.token_urlsafe(16)}
    address = f"ops_{suffix}@example.com"
    user = client.post(f"{API}/auth/register", json={**credentials, "email": address, "organisation": f"Org {suffix}"}).json()
    tenant = user["tenant_id"]
    now = datetime.now(timezone.utc)
    db_call(client, lambda db: db["connections"].insert_one({
        "tenant_id": tenant, "connector": "m365", "status": "connected", "connected_at": now, "last_data_at": now, "errors": {},
    }))
    yield tenant, address
    db_call(client, lambda db: db["connections"].delete_many({"tenant_id": tenant}))


def connector_emails(client, address):
    return db_call(client, lambda db: db["notifications"].find({"email": address, "kind": "connector_health"}).sort("created_at", 1).to_list(10))


def test_administrators_hear_when_their_connector_fails_and_recovers(client, mailbox, organisation):
    from core.services import platform_health

    tenant, address = organisation
    db_call(client, lambda db: db["connections"].update_one({"tenant_id": tenant}, {"$set": {
        "status": "error", "errors": {"signins": "Microsoft Graph answered 401"}}}))
    run(client, platform_health.check_once)
    run(client, platform_health.check_once)
    [failing] = connector_emails(client, address)
    assert failing["subject"] == "[UTDRS] The Microsoft 365 connection needs attention"

    db_call(client, lambda db: db["connections"].update_one({"tenant_id": tenant}, {"$set": {"status": "connected", "errors": {}}}))
    run(client, platform_health.check_once)
    assert [e["subject"] for e in connector_emails(client, address)][-1] == "[UTDRS] The Microsoft 365 connection is working again"


def test_a_connector_that_goes_quiet_is_reported(client, mailbox, organisation):
    from core.services import platform_health

    tenant, address = organisation
    db_call(client, lambda db: db["connections"].update_one({"tenant_id": tenant}, {"$set": {
        "last_data_at": datetime.now(timezone.utc) - timedelta(hours=30)}}))
    run(client, platform_health.check_once)
    [quiet] = connector_emails(client, address)
    assert "Nothing has arrived for 30 hours" in (quiet["text"] or "")
