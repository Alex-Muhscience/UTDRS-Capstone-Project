"""Files attached to cases."""
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from config import settings
from tests.e2e.test_cases import alert_about

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def organisation(client, monkeypatch, role="admin"):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"cf_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"cf_{suffix}@example.com", "organisation": f"Org {suffix}"})
    return {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}


@pytest.fixture
def admin(client, monkeypatch):
    return organisation(client, monkeypatch)


@pytest.fixture
def case_id(client, admin):
    return alert_about(client, admin, user=f"u-{uuid.uuid4().hex[:6]}")["case_id"]


def upload(client, auth, case_id, name, data, content_type="text/plain"):
    return client.post(f"{API}/cases/{case_id}/attachments", files={"file": (name, data, content_type)}, headers=auth)


def test_a_file_is_kept_with_its_hash_and_downloaded_as_it_was(client, admin, case_id):
    data = b"Subject: Invoice\r\n\r\nPlease pay." * 100
    added = upload(client, admin, case_id, "../../suspicious email.eml", data, "message/rfc822")
    assert added.status_code == 201, added.text
    attachment = added.json()
    assert attachment["name"] == "suspicious email.eml"
    assert attachment["sha256"] == hashlib.sha256(data).hexdigest() and attachment["size"] == len(data)

    case = client.get(f"{API}/cases/{case_id}", headers=admin).json()
    assert case["attachments"][0]["id"] == attachment["id"]
    assert case["timeline"][-1]["kind"] == "attachment_added"

    downloaded = client.get(f"{API}/cases/{case_id}/attachments/{attachment['id']}", headers=admin)
    assert downloaded.status_code == 200 and downloaded.content == data
    assert downloaded.headers["content-type"] == "application/octet-stream"
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert downloaded.headers["x-checksum-sha256"] == attachment["sha256"]

    log = client.get(f"{API}/audit-log/", params={"action": "cases.add_attachment"}, headers=admin).json()
    assert log[0]["details"]["file"]["sha256"] == attachment["sha256"]


def test_a_page_uploaded_cannot_run_in_the_dashboard(client, admin, case_id):
    attachment = upload(client, admin, case_id, "x.html", b"<script>alert(1)</script>", "text/html").json()
    response = client.get(f"{API}/cases/{case_id}/attachments/{attachment['id']}", headers=admin)
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]


def test_files_are_limited(client, admin, case_id, monkeypatch):
    monkeypatch.setattr(settings, "CASE_ATTACHMENT_MAX_MB", 1)
    assert upload(client, admin, case_id, "big.bin", b"x" * (1024 * 1024 + 1)).status_code == 413
    assert upload(client, admin, case_id, "empty.txt", b"").status_code == 422
    from core.services import case_files

    monkeypatch.setattr(case_files, "MAX_PER_CASE", 2)
    assert upload(client, admin, case_id, "1.txt", b"1").status_code == 201
    assert upload(client, admin, case_id, "2.txt", b"2").status_code == 201
    assert upload(client, admin, case_id, "3.txt", b"3").status_code == 422


def test_files_stay_in_their_organisation(client, admin, case_id, monkeypatch):
    attachment = upload(client, admin, case_id, "a.txt", b"secret").json()
    other = organisation(client, monkeypatch)
    assert client.get(f"{API}/cases/{case_id}/attachments/{attachment['id']}", headers=other).status_code == 404
    assert client.delete(f"{API}/cases/{case_id}/attachments/{attachment['id']}", headers=other).status_code == 404
    assert upload(client, other, case_id, "b.txt", b"x").status_code == 404


def test_removing_a_file(client, admin, case_id, monkeypatch):
    attachment = upload(client, admin, case_id, "a.txt", b"remove me").json()
    assert client.delete(f"{API}/cases/{case_id}/attachments/{attachment['id']}", headers=admin).status_code == 204
    case = client.get(f"{API}/cases/{case_id}", headers=admin).json()
    assert case["attachments"] == [] and case["timeline"][-1]["kind"] == "attachment_removed"
    assert client.get(f"{API}/cases/{case_id}/attachments/{attachment['id']}", headers=admin).status_code == 404


def test_retention_takes_a_case_s_files_with_it(client, admin, case_id):
    from core.database.connection import get_database
    from core.services import retention
    from core.tenancy import tenant_context

    attachment = upload(client, admin, case_id, "old.txt", b"old evidence").json()
    client.patch(f"{API}/cases/{case_id}", json={"status": "closed"}, headers=admin)
    tenant = client.get(f"{API}/tenants/current", headers=admin).json()["id"]

    async def age_and_run():
        from bson import ObjectId

        await get_database()["cases"].update_one({"_id": ObjectId(case_id)}, {"$set": {"updated_at": datetime.now(timezone.utc) - timedelta(days=4000)}})
        await get_database()["alerts"].update_many({"case_id": case_id}, {"$set": {"status": "closed", "updated_at": datetime.now(timezone.utc) - timedelta(days=4000)}})
        with tenant_context(tenant):
            await retention.run()
        return await get_database()["case_files.files"].count_documents({"_id": ObjectId(attachment["id"])})

    assert client.portal.call(age_and_run) == 0
