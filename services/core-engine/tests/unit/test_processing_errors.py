"""A failure while processing is an error the gateway sees (and retries), not "no threat"."""
import pytest


@pytest.mark.asyncio
async def test_a_failure_is_raised_not_reported_as_clean(monkeypatch):
    from core.services import event_processor

    class Broken:
        async def detect_threats(self, event):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(event_processor, "get_detection_engine", lambda: Broken())
    with pytest.raises(RuntimeError):
        await event_processor.process_event({"source": "x", "event_type": "process", "timestamp": "2026-01-01T00:00:00", "data": {}})
