"""API keys and their scopes, and the audit log."""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

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
def admin(client):
    response = client.post(f"{API}/auth/login", data={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="module")
def analyst(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"audit_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"audit_{suffix}@example.com"})
    token = client.post(f"{API}/auth/login", data=credentials).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def new_key(client, admin, scopes, **extra):
    response = client.post(f"{API}/api-keys/", json={"name": f"key-{uuid.uuid4().hex[:6]}", "scopes": scopes, **extra}, headers=admin)
    assert response.status_code == 201, response.text
    body = response.json()
    return body["api_key"], {"Authorization": f"Bearer {body['key']}"}, body["key"]


def event():
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "network", "source": "firewall", "description": "Connection allowed"}


def test_a_key_is_shown_once_and_stored_only_as_a_hash(client, admin):
    record, _, key = new_key(client, admin, ["events:write"])
    assert key.startswith(f"utdrs_{record['prefix']}_")
    listed = next(k for k in client.get(f"{API}/api-keys/", headers=admin).json() if k["id"] == record["id"])
    assert "key" not in listed and "hash" not in listed
    assert listed["scopes"] == ["events:write"]


def test_a_key_can_do_what_its_scopes_allow_and_nothing_else(client, admin):
    _, auth, _ = new_key(client, admin, ["events:write", "alerts:read"])
    assert client.post(f"{API}/events/", json=event(), headers=auth).status_code == 201
    assert client.get(f"{API}/alerts/", headers=auth).status_code == 200
    # Not granted:
    assert client.get(f"{API}/events/", headers=auth).status_code == 403
    assert client.get(f"{API}/assets/", headers=auth).status_code == 403
    assert client.post(f"{API}/alerts/", json={"title": "x", "description": "x", "severity": "low", "source": "x", "type": "x"}, headers=auth).status_code == 403
    response = client.get(f"{API}/assets/", headers=auth)
    assert response.json()["detail"] == "This API key does not have the assets:read scope"


def test_a_key_never_acts_as_an_administrator(client, admin):
    _, auth, _ = new_key(client, admin, ["rules:write", "rules:read"])
    rule = {"name": f"r-{uuid.uuid4().hex[:6]}", "description": "x", "rule_type": "signature", "detection_source": "endpoint", "severity": "low", "logic": "a == 1"}
    assert client.post(f"{API}/detection/rules", json=rule, headers=auth).status_code == 403
    assert client.get(f"{API}/users/", headers=auth).status_code == 403
    assert client.post(f"{API}/api-keys/", json={"name": "x", "scopes": ["events:read"]}, headers=auth).status_code == 403
    assert client.get(f"{API}/audit-log/", headers=auth).status_code == 403


def test_revoked_expired_and_unknown_keys_are_refused(client, admin):
    record, auth, _ = new_key(client, admin, ["alerts:read"])
    assert client.get(f"{API}/alerts/", headers=auth).status_code == 200
    assert client.delete(f"{API}/api-keys/{record['id']}", headers=admin).json()["revoked_at"]
    assert client.get(f"{API}/alerts/", headers=auth).status_code == 401
    assert client.delete(f"{API}/api-keys/{record['id']}", headers=admin).status_code == 404

    record, auth, _ = new_key(client, admin, ["alerts:read"], expires_in_days=1)

    async def expire():
        from bson import ObjectId
        from core.database.connection import get_database

        await get_database()["api_keys"].update_one(
            {"_id": ObjectId(record["id"])}, {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}}
        )

    client.portal.call(expire)
    assert client.get(f"{API}/alerts/", headers=auth).status_code == 401
    assert client.get(f"{API}/alerts/", headers={"Authorization": "Bearer utdrs_00000000_nope"}).status_code == 401


def test_unknown_scopes_are_refused(client, admin):
    response = client.post(f"{API}/api-keys/", json={"name": "x", "scopes": ["everything"]}, headers=admin)
    assert response.status_code == 422


def entries(client, admin, **params):
    response = client.get(f"{API}/audit-log/", params=params, headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def test_sign_ins_are_audited(client, admin):
    # A wrong password for an account is in its organisation's log.
    username = f"member_{uuid.uuid4().hex[:6]}"
    client.post(f"{API}/auth/register", json={"username": username, "email": f"{username}@example.com", "password": secrets.token_urlsafe(16)})
    client.post(f"{API}/auth/login", data={"username": username, "password": "wrong"})
    failed = next(e for e in entries(client, admin, action="auth.login_failed") if e["actor"].get("name") == username)
    assert failed["outcome"] == "denied" and failed["actor"]["type"] == "anonymous"

    # A name nobody has belongs to no organisation: its attempt is in the platform's log.
    nobody = f"nobody_{uuid.uuid4().hex[:6]}"
    client.post(f"{API}/auth/login", data={"username": nobody, "password": "wrong"})
    assert not [e for e in entries(client, admin, action="auth.login_failed") if e["actor"].get("name") == nobody]

    succeeded = entries(client, admin, action="auth.login_succeeded")[0]
    assert succeeded["actor"]["type"] == "user" and succeeded["outcome"] == "success"


def test_changes_are_audited_with_who_made_them(client, admin, analyst):
    rule = {"name": f"audited-{uuid.uuid4().hex[:6]}", "description": "x", "rule_type": "signature", "detection_source": "endpoint", "severity": "low", "status": "testing", "logic": "a == 1"}
    created = client.post(f"{API}/detection/rules", json=rule, headers=admin).json()

    entry = entries(client, admin, target_id=created["id"])[0]
    assert entry["action"] == "rules.create_rule"
    assert entry["actor"]["type"] == "user" and entry["actor"]["name"] == os.environ["ADMIN_USERNAME"]
    assert entry["details"]["request"]["name"] == rule["name"]

    client.patch(f"{API}/detection/rules/{created['id']}/status", params={"status": "disabled"}, headers=admin)
    actions = [e["action"] for e in entries(client, admin, target_type="rule", target_id=created["id"])]
    assert actions == ["rules.update_rule_status", "rules.create_rule"]

    # An analyst's attempt is refused, and recorded as refused.
    assert client.post(f"{API}/detection/rules", json={**rule, "name": "nope"}, headers=analyst).status_code == 403
    denied = entries(client, admin, action="rules.create_rule")[0]
    assert denied["outcome"] == "denied" and denied["actor"]["role"] == "analyst"


def test_changes_made_with_a_key_name_the_key(client, admin):
    record, auth, _ = new_key(client, admin, ["assets:write", "assets:read"])
    asset = client.post(f"{API}/assets/", json={"name": f"srv-{uuid.uuid4().hex[:6]}", "asset_type": "server"}, headers=auth).json()
    entry = entries(client, admin, action="assets.create_asset")[0]
    assert entry["actor"] == {"type": "api_key", "id": record["id"], "name": record["name"], "scopes": ["assets:read", "assets:write"]}
    assert entry["details"]["request"]["name"] == asset["name"]

    created = entries(client, admin, action="api_key.created", target_id=record["id"])
    assert created and created[0]["details"]["scopes"] == ["assets:read", "assets:write"]


def test_secrets_never_reach_the_log():
    from core.services.audit import _summary

    assert _summary({"username": "a", "password": "p", "nested": {"new_password": "q"}}) == {
        "username": "a", "password": "[hidden]", "nested": {"new_password": "[hidden]"},
    }


def test_the_chain_shows_tampering(client, admin):
    assert client.get(f"{API}/audit-log/verify", headers=admin).json()["ok"] is True

    async def tamper(change):
        from core.services import tenants
        from core.tenancy import scoped, set_tenant
        from core.database.connection import get_database

        set_tenant(await tenants.default_id())
        log = scoped(get_database(), "audit_log")
        newest = await log.find_one({}, sort=[("seq", -1)])
        await change(log, newest)
        return newest

    async def edit(log, entry):
        await log.update_one({"_id": entry["_id"]}, {"$set": {"outcome": "success", "actor.name": "someone else"}})

    edited = client.portal.call(tamper, edit)
    result = client.get(f"{API}/audit-log/verify", headers=admin).json()
    assert result == {"ok": False, "checked": edited["seq"] - 1, "problem": f"Entry {edited['seq']} has been altered", "note": None}

    async def remove_and_age(log, entry):
        from core.database.connection import get_database
        from core.tenancy import scoped

        await log.delete_one({"_id": entry["_id"]})
        # Long enough ago that it cannot still be being written.
        await scoped(get_database(), "audit_log_head").update_one(
            {"kind": "head"}, {"$set": {"at": datetime.now(timezone.utc) - timedelta(minutes=1)}}
        )

    client.portal.call(tamper, remove_and_age)
    assert "missing" in client.get(f"{API}/audit-log/verify", headers=admin).json()["problem"]


def test_entries_written_at_once_still_form_one_chain(client, admin):
    import asyncio

    async def burst():
        from core.services import audit, tenants
        from core.tenancy import set_tenant

        set_tenant(await tenants.default_id())

        before = await audit.verify()
        await asyncio.gather(*(audit.record("test.concurrent", actor={"type": "system"}, details={"n": n}) for n in range(40)))
        return before, await audit.verify()

    before, after = client.portal.call(burst)
    # The earlier test left the chain broken on purpose; what matters is that these 40 joined it in order.
    written = entries(client, admin, action="test.concurrent", limit=100)
    assert len(written) == 40
    seqs = sorted(e["seq"] for e in written)
    assert seqs == list(range(seqs[0], seqs[0] + 40))
    by_seq = {e["seq"]: e for e in written}
    assert all(by_seq[s]["prev_hash"] == by_seq[s - 1]["hash"] for s in seqs[1:])


def test_a_gap_is_reported_only_once_its_entry_should_have_been_written(client, admin):
    async def scenario():
        from core.database.connection import get_database
        from core.services import audit, tenants
        from core.tenancy import scoped, set_tenant

        # A fresh organisation, so its chain starts from nothing.
        set_tenant(await tenants.create(f"Gap test {uuid.uuid4().hex[:6]}"))
        database = get_database()
        head = scoped(database, "audit_log_head")
        for n in range(3):
            await audit.record("test.gap", actor={"type": "system"}, details={"n": n})
        # The next number is taken but its entry is not stored yet: it is being written.
        await head.update_one({"kind": "head"}, {"$inc": {"seq": 1}, "$set": {"at": datetime.now(timezone.utc)}})
        writing = await audit.verify()
        # A minute later, it never arrived.
        await head.update_one({"kind": "head"}, {"$set": {"at": datetime.now(timezone.utc) - timedelta(minutes=1)}})
        missing = await audit.verify()
        return writing, missing

    writing, missing = client.portal.call(scenario)
    assert writing["ok"] is True and writing["checked"] == 3 and "still being written" in writing["note"]
    assert missing == {"ok": False, "checked": 3, "problem": "The log should end at entry 4; entries after 3 are missing"}
