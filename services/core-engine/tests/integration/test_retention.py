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


@pytest.mark.asyncio
async def test_an_event_the_gateway_sends_again_is_kept_once(mongo):
    from core.detection.correlation_detector import CorrelationDetector

    detector = CorrelationDetector()
    detector.db = mongo
    for attempt in ("first", "second"):
        event = {"id": attempt, "event_type": "authentication", "timestamp": datetime.now(timezone.utc).isoformat(),
                 "data": {"gateway_event_id": "665f1c2ab1e2c3d4e5f60aaa"}}
        await detector.detect(event)
    stored = await mongo["events"].find({"data.gateway_event_id": "665f1c2ab1e2c3d4e5f60aaa"}).to_list(10)
    assert [e["id"] for e in stored] == ["second"]


@pytest.mark.asyncio
async def test_a_burst_of_failed_sign_ins_is_one_correlation(mongo):
    """
    Events arriving one by one, as they do: the fifth failed sign-in in ten minutes raises the
    correlation, once; the ones after it in the hour do not raise it again.
    """
    from datetime import timedelta

    from core.detection.correlation_detector import CorrelationDetector
    from core.detection.identity_detector import IdentityDetector

    await IdentityDetector().ensure_indexes()
    detector = CorrelationDetector()
    detector.db = mongo
    user = f"ann-{datetime.now().timestamp()}"
    start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=30)
    raised = []
    for i in range(12):
        failed = {"id": f"a{i}", "event_type": "authentication", "source": "vpn", "timestamp": (start + timedelta(minutes=2 * i)).isoformat(),
                  "data": {"status": "failed", "user_id": user}}
        result = await detector.detect(failed)
        if result and result.get("name") == "Multiple Failed Logins":
            raised.append(i)
        # Noise in between, which must not change anything.
        await detector.detect({"id": f"f{i}", "event_type": "file", "source": "edr",
                               "timestamp": (start + timedelta(minutes=2 * i, seconds=30)).isoformat(), "data": {"path": f"/tmp/{i}"}})
    assert raised == [4]
