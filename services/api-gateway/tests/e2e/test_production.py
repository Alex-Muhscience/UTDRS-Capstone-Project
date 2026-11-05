"""What a production deployment shows the outside world."""
import os

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def test_every_response_asks_browsers_for_https_and_safe_handling(client):
    headers = client.get(f"{API}/health").headers
    assert headers["strict-transport-security"].startswith("max-age=63072000")
    assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
    assert headers["x-xss-protection"] == "0"


def test_uptime_monitors_can_use_head(client):
    for path in ("/health", "/health/ready", "/health/db"):
        assert client.head(f"{API}{path}").status_code == 200, path


def test_a_failing_database_is_reported_without_its_details(client, monkeypatch):
    from api.routes import health

    class Broken:
        async def command(self, *_):
            raise RuntimeError("connection refused to db-host-7.internal:27017 as user secret")

    monkeypatch.setattr(health, "get_database", lambda: Broken())
    for path in ("/health/db", "/health/ready"):
        response = client.get(f"{API}{path}")
        assert response.status_code == 503 and "db-host" not in response.text and "secret" not in response.text, path
