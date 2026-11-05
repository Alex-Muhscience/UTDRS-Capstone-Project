"""Exporting the audit log, and checking an export outside UTDRS."""
import csv
import io
import json
import os
import secrets
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
VERIFY = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "verify_audit_export.py")


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin(client, monkeypatch):
    """A new organisation's administrator, with a little history."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"aud_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"aud_{suffix}@example.com", "organisation": f"Org {suffix}"})
    auth = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    client.patch(f"{API}/tenants/current", json={"name": f"Renamed {suffix} — café"}, headers=auth)
    return auth


def verify(tmp_path, text):
    path = tmp_path / "export.jsonl"
    path.write_text(text, encoding="utf-8")
    return subprocess.run([sys.executable, VERIFY, str(path)], capture_output=True, text=True)


def test_an_export_can_be_checked_outside_utdrs(client, admin, tmp_path):
    response = client.get(f"{API}/audit-log/export", headers=admin)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment" in response.headers["content-disposition"]
    lines = [json.loads(line) for line in response.text.splitlines()]
    assert lines[0]["seq"] == 1 and [e["seq"] for e in lines] == sorted(e["seq"] for e in lines)
    assert any(e["action"] == "tenant.renamed" for e in lines)
    assert all("tenant_id" not in e for e in lines)

    checked = verify(tmp_path, response.text)
    assert checked.returncode == 0, checked.stdout
    assert checked.stdout.startswith("OK:")

    # Change one entry: the check finds it.
    tampered = response.text.replace('"tenant.renamed"', '"tenant.removed"', 1)
    found = verify(tmp_path, tampered)
    assert found.returncode == 1 and "has been altered" in found.stdout
    # Remove one: the chain no longer follows.
    dropped = "\n".join(line for i, line in enumerate(response.text.splitlines()) if i != 1) + "\n"
    assert "does not follow" in verify(tmp_path, dropped).stdout or "gaps" in verify(tmp_path, dropped).stdout


def test_exports_are_filtered_and_recorded(client, admin):
    renamed = client.get(f"{API}/audit-log/export", params={"action": "tenant"}, headers=admin).text.splitlines()
    assert renamed and all(json.loads(line)["action"].startswith("tenant.") for line in renamed)
    log = client.get(f"{API}/audit-log/", params={"action": "audit.exported"}, headers=admin).json()
    assert log and log[0]["details"]["format"] == "jsonl"


def test_a_csv_export_for_spreadsheets(client, admin):
    response = client.get(f"{API}/audit-log/export", params={"format": "csv"}, headers=admin)
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    renamed = next(r for r in rows if r["action"] == "tenant.renamed")
    assert renamed["actor_type"] == "user" and renamed["target_type"] == "tenant" and len(renamed["hash"]) == 64
    assert "café" in renamed["changes"] or "caf" in renamed["changes"]


def test_only_administrators_export(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "join")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"ana_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"ana_{suffix}@example.com"})
    analyst = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    assert client.get(f"{API}/audit-log/export", headers=analyst).status_code == 403
