"""The engine's own copy of events expires."""
from datetime import datetime, timedelta, timezone

import pytest

from config import settings
from tests.conftest import requires_mongodb

pytestmark = requires_mongodb


@pytest.mark.asyncio
async def test_events_expire_after_the_retention_period(mongo, monkeypatch):
    from app import expire_old_events

    old = (datetime.now(timezone.utc) - timedelta(days=settings.EVENT_RETENTION_DAYS + 1)).isoformat()
    recent = datetime.now(timezone.utc).isoformat()
    await mongo["events"].insert_many([{"id": "old", "timestamp": old}, {"id": "recent", "timestamp": recent}])

    await expire_old_events()
    indexes = await mongo["events"].index_information()
    assert indexes["stored_at_ttl"]["expireAfterSeconds"] == settings.EVENT_RETENTION_DAYS * 86400
    assert [e["id"] async for e in mongo["events"].find({}, {"id": 1})] == ["recent"]  # from before the index, by timestamp

    # A changed period replaces the index.
    monkeypatch.setattr(settings, "EVENT_RETENTION_DAYS", 7)
    await expire_old_events()
    assert (await mongo["events"].index_information())["stored_at_ttl"]["expireAfterSeconds"] == 7 * 86400


@pytest.mark.asyncio
async def test_stored_events_carry_when_they_were_stored(mongo):
    from core.detection.correlation_detector import CorrelationDetector

    detector = CorrelationDetector()
    detector.db = mongo
    event = {"id": "e1", "event_type": "process", "timestamp": datetime.now(timezone.utc).isoformat(), "data": {}}
    await detector.detect(event)
    stored = await mongo["events"].find_one({"id": "e1"})
    assert isinstance(stored["stored_at"], datetime) and "stored_at" not in event


@pytest.mark.asyncio
async def test_message_text_is_judged_but_not_kept(mongo):
    from core.detection.correlation_detector import CorrelationDetector

    detector = CorrelationDetector()
    detector.db = mongo
    event = {"id": "m1", "event_type": "email", "timestamp": datetime.now(timezone.utc).isoformat(),
             "data": {"subject": "Invoice", "body": "confirm your password", "sender": "x@evil.example"}}
    await detector.detect(event)
    stored = await mongo["events"].find_one({"id": "m1"})
    assert stored["data"] == {"subject": "Invoice", "sender": "x@evil.example"}
    assert event["data"]["body"] == "confirm your password"  # the detectors still see it
