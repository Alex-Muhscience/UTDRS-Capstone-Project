"""Handing events to analysis workers through Redis Streams."""
import os
import secrets
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from config import settings
from core.services import core_engine_client
from core.services.core_engine_client import CoreEngineClient
from tests.e2e.test_detection_pipeline import FakeEngine, process_event

pytestmark = pytest.mark.skipif(
    not (os.environ.get("UTDRS_RUN_DB_TESTS") and os.environ.get("TEST_REDIS_URL")), reason="MONGODB_URI and TEST_REDIS_URL needed"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def engine(monkeypatch):
    fake = FakeEngine()
    monkeypatch.setattr(core_engine_client, "get_core_engine_client",
                        lambda: CoreEngineClient("http://core-engine", token="t", transport=httpx.MockTransport(fake.handler)))
    return fake


@pytest.fixture
def stream(client, monkeypatch):
    """A stream of its own, with dedicated workers (the API does not analyse)."""
    from core.services import analysis_stream

    monkeypatch.setattr(settings, "REDIS_URL", os.environ["TEST_REDIS_URL"])
    monkeypatch.setattr(settings, "ANALYSIS_IN_API", False)
    monkeypatch.setattr(analysis_stream, "STREAM", f"utdrs:test:{uuid.uuid4().hex[:8]}")
    monkeypatch.setattr(analysis_stream, "_client", None)

    async def setup():
        await analysis_stream.ensure_group()

    client.portal.call(setup)
    yield analysis_stream

    async def teardown():
        await analysis_stream.client().delete(analysis_stream.STREAM)
        await analysis_stream.close()

    client.portal.call(teardown)


@pytest.fixture(scope="module")
def auth(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"st_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"st_{suffix}@example.com"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}


def analysis(client, auth, event_id):
    return client.get(f"{API}/events/{event_id}", headers=auth).json()["metadata"]["analysis"]


def round_of(client, consumer):
    from core.services import detection_pipeline

    async def once():
        return await detection_pipeline.stream_round(consumer, block_ms=100)

    return client.portal.call(once)


def pending(client, stream):
    async def count():
        return (await stream.status())["pending"]

    return client.portal.call(count)


def test_workers_take_events_from_the_stream(client, auth, engine, stream):
    threat = client.post(f"{API}/events/", json=process_event("vssadmin delete shadows /all"), headers=auth).json()["id"]
    clean = client.post(f"{API}/events/", json=process_event("notepad.exe"), headers=auth).json()["id"]
    # The API only queued them: workers analyse.
    assert analysis(client, auth, threat)["status"] == "queued"
    assert round_of(client, "worker-a") == 2
    assert analysis(client, auth, threat)["status"] == "threat" and analysis(client, auth, clean)["status"] == "clean"
    assert pending(client, stream) == 0  # acknowledged
    assert round_of(client, "worker-a") == 0  # nothing left


def test_work_a_dead_worker_took_is_taken_over(client, auth, engine, stream, monkeypatch):
    event_id = client.post(f"{API}/events/", json=process_event("notepad.exe"), headers=auth).json()["id"]

    async def take_and_die():
        return await stream.take("worker-dead", 10, block_ms=100)

    assert len(client.portal.call(take_and_die)) == 1
    assert pending(client, stream) == 1
    monkeypatch.setattr(stream, "STALE_MS", 0)
    assert round_of(client, "worker-b") == 1
    assert analysis(client, auth, event_id)["status"] == "clean" and pending(client, stream) == 0


def test_nothing_is_lost_when_redis_is_unreachable(client, auth, engine, monkeypatch):
    from core.services import analysis_stream, detection_pipeline

    monkeypatch.setattr(settings, "REDIS_URL", "redis://nowhere.invalid:6379/0")
    monkeypatch.setattr(settings, "ANALYSIS_IN_API", False)
    monkeypatch.setattr(analysis_stream, "_client", None)
    created = client.post(f"{API}/events/", json=process_event("notepad.exe"), headers=auth)
    assert created.status_code == 201
    event_id = created.json()["id"]
    assert analysis(client, auth, event_id)["status"] == "queued"
    client.portal.call(detection_pipeline.analyse_due)  # the database sweep, the safety net
    assert analysis(client, auth, event_id)["status"] == "clean"
    client.portal.call(analysis_stream.close)


def test_replayed_events_go_through_the_stream(client, auth, engine, stream):
    engine.fail = True
    event_id = client.post(f"{API}/events/", json=process_event("notepad.exe"), headers=auth).json()["id"]
    round_of(client, "worker-c")  # the engine is down: queued again with back-off

    async def fail_it():
        from bson import ObjectId

        from core.database.connection import get_database

        await get_database()["events"].update_one({"_id": ObjectId(event_id)}, {"$set": {"metadata.analysis.status": "error"}})

    client.portal.call(fail_it)
    engine.fail = False
    assert client.post(f"{API}/events/{event_id}/reanalyse", headers=auth).status_code == 200
    assert round_of(client, "worker-c") == 1
    assert analysis(client, auth, event_id)["status"] == "clean"
