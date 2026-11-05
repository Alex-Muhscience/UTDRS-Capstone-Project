"""The ingestion API: batches, external ids, idempotency keys and compression."""
import gzip
import json
import os
import secrets
import uuid
from datetime import datetime, timezone

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


@pytest.fixture(scope="module")
def auth(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"ing_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"ing_{suffix}@example.com"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}


def event(**fields):
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "authentication", "source": "vpn",
            "description": "Sign-in", **fields}


def test_an_event_sent_twice_is_stored_once(client, auth):
    external = uuid.uuid4().hex
    first = client.post(f"{API}/events/", json=event(external_id=external), headers=auth)
    assert first.status_code == 201
    again = client.post(f"{API}/events/", json=event(external_id=external), headers=auth)
    assert again.status_code == 200
    assert again.headers["X-Duplicate"] == "true"
    assert again.json()["id"] == first.json()["id"]
    # Another source may use the same id.
    other = client.post(f"{API}/events/", json=event(external_id=external, source="firewall"), headers=auth)
    assert other.status_code == 201 and other.json()["id"] != first.json()["id"]


def test_a_request_repeated_with_its_idempotency_key_gets_the_first_answer(client, auth):
    key = {**auth, "Idempotency-Key": uuid.uuid4().hex}
    body = event(description="Once")
    first = client.post(f"{API}/events/", json=body, headers=key)
    again = client.post(f"{API}/events/", json=body, headers=key)
    assert (again.status_code, again.json()["id"]) == (first.status_code, first.json()["id"])
    assert again.headers["Idempotent-Replayed"] == "true"
    different = client.post(f"{API}/events/", json={**body, "description": "Something else"}, headers=key)
    assert different.status_code == 409


def test_a_batch_stores_the_valid_events_and_lists_the_rest(client, auth):
    external = uuid.uuid4().hex
    batch = [event(external_id=external), {"source": "vpn"}, event(external_id=external), event()]
    response = client.post(f"{API}/events/batch", json={"events": batch}, headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["created"], body["duplicates"], body["rejected"]) == (2, 1, 1)
    assert [r["status"] for r in body["results"]] == ["created", "rejected", "duplicate", "created"]
    assert body["results"][2]["id"] == body["results"][0]["id"]
    assert "timestamp" in body["results"][1]["error"] or "event_type" in body["results"][1]["error"]
    stored = client.get(f"{API}/events/{body['results'][3]['id']}", headers=auth)
    assert stored.status_code == 200


def test_batches_are_limited(client, auth):
    assert client.post(f"{API}/events/batch", json={"events": [event()] * 501}, headers=auth).status_code == 422
    assert client.post(f"{API}/events/batch", json={"events": []}, headers=auth).status_code == 422


def test_a_gzipped_batch_is_accepted(client, auth):
    body = gzip.compress(json.dumps({"events": [event(description=f"Compressed {i}") for i in range(50)]}).encode())
    response = client.post(f"{API}/events/batch", content=body,
                           headers={**auth, "Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert response.status_code == 200, response.text
    assert response.json()["created"] == 50


def test_compression_cannot_be_used_to_send_too_much(client, auth):
    bomb = gzip.compress(b'{"events": [' + b" " * (11 * 1024 * 1024) + b"]}")
    response = client.post(f"{API}/events/batch", content=bomb, headers={**auth, "Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert response.status_code == 413
    broken = client.post(f"{API}/events/batch", content=b"not gzip", headers={**auth, "Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert broken.status_code == 400
    other = client.post(f"{API}/events/batch", content=b"{}", headers={**auth, "Content-Type": "application/json", "Content-Encoding": "br"})
    assert other.status_code == 415


def test_large_answers_are_compressed_for_clients_that_accept_it(client, auth):
    response = client.get(f"{API}/events/", params={"limit": 100}, headers={**auth, "Accept-Encoding": "gzip"})
    assert response.status_code == 200
    assert response.headers.get("content-encoding") == "gzip"
