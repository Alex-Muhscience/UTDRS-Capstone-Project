"""Identity correlations, through the detection API: sign-ins in, alerts out."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests.conftest import requires_mongodb

pytestmark = requires_mongodb

NAIROBI = (-1.29, 36.82)
MOMBASA = (-4.04, 39.67)
AMSTERDAM = (52.37, 4.89)


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client
        import os

        from pymongo import MongoClient

        with MongoClient(os.environ["MONGODB_URI"]) as sync_client:
            sync_client.drop_database(os.environ["DB_NAME"])


def sign_in(client, user, ip="203.0.113.5", status="failure", error_code=50126, at=None, where=None, tenant="t1"):
    data = {"user": user, "source_ip": ip, "status": status, "error_code": 0 if status == "success" else error_code}
    if where:
        data.update(latitude=where[0], longitude=where[1], city="here")
    response = client.post("/detections/process", json={
        "tenant_id": tenant, "source": "m365", "event_type": "authentication",
        "timestamp": (at or datetime.now(timezone.utc)).isoformat(), "data": data,
    })
    assert response.status_code == 200, response.text
    return response.json()


def title(alert):
    return alert["title"] if alert else None


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:6]}@contoso.example"


def test_password_spraying_from_one_address(client):
    ip = f"198.51.100.{uuid.uuid4().int % 250}"
    results = [sign_in(client, unique("spray"), ip=ip, tenant="spray") for _ in range(10)]
    assert all(title(r) != "Password spraying" for r in results[:9])
    alert = results[9]
    assert title(alert) == "Password spraying" and alert["severity"] == "high"
    assert "T1110.003" in alert["details"]["mitre_techniques"] and "brute-force" in alert["details"]["tags"]
    assert len(alert["event_ids"]) == 10
    # Once per address per hour: the eleventh failure does not raise it again.
    assert title(sign_in(client, unique("spray"), ip=ip, tenant="spray")) != "Password spraying"


def test_guessing_one_accounts_password(client):
    user = unique("guess")
    results = [sign_in(client, user, ip=f"192.0.2.{n}") for n in range(10)]
    assert title(results[9]) == "Password guessing against one account" and "T1110.001" in results[9]["details"]["mitre_techniques"]


def test_success_after_failures(client):
    user = unique("stuffed")
    for _ in range(5):
        sign_in(client, user)
    alert = sign_in(client, user, status="success")
    assert title(alert) == "Sign-in succeeded after repeated failures" and alert["severity"] == "high"
    assert {"T1110", "T1078"} <= set(alert["details"]["mitre_techniques"])


def test_mfa_fatigue(client):
    user = unique("fatigue")
    results = [sign_in(client, user, error_code=500121) for _ in range(5)]
    assert title(results[4]) == "Possible MFA fatigue attack" and "T1621" in results[4]["details"]["mitre_techniques"]


def test_impossible_travel(client):
    user = unique("traveller")
    start = datetime.now(timezone.utc) - timedelta(minutes=40)
    assert title(sign_in(client, user, status="success", at=start, where=NAIROBI)) != "Impossible travel"
    alert = sign_in(client, user, status="success", at=start + timedelta(minutes=30), where=AMSTERDAM)
    assert title(alert) == "Impossible travel" and "T1078" in alert["details"]["mitre_techniques"]
    assert alert["details"]["detection"]["details"]["km"] > 6000


def test_a_plausible_journey_is_not_impossible(client):
    user = unique("commuter")
    start = datetime.now(timezone.utc) - timedelta(hours=3)
    sign_in(client, user, status="success", at=start, where=NAIROBI)
    assert title(sign_in(client, user, status="success", at=start + timedelta(hours=2), where=MOMBASA)) != "Impossible travel"


def test_organisations_are_correlated_apart(client):
    ip = f"198.51.100.{uuid.uuid4().int % 250}"
    for n in range(9):
        sign_in(client, unique("a"), ip=ip, tenant="org-a")
    # The tenth failure from that address is another organisation's: no spraying in either.
    assert title(sign_in(client, unique("b"), ip=ip, tenant="org-b")) != "Password spraying"
