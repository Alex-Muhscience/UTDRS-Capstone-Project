"""Sign-in throttling, client addresses behind proxies, and unique asset names."""
import asyncio
import os
import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def new_account(client):
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"guard_{suffix}", "password": secrets.token_urlsafe(16)}
    response = client.post("/api/v1/auth/register", json={**credentials, "email": f"guard_{suffix}@example.com"})
    assert response.status_code == 200, response.text
    return credentials


def login(client, username, password, forwarded_for=None):
    headers = {"X-Forwarded-For": forwarded_for} if forwarded_for else {}
    return client.post("/api/v1/auth/login", data={"username": username, "password": password}, headers=headers)


def test_repeated_wrong_passwords_lock_that_account_from_that_address(client):
    account = new_account(client)
    for _ in range(settings.LOGIN_MAX_FAILURES_PER_ACCOUNT):
        assert login(client, account["username"], "wrong-password").status_code == 401

    # Now even the right password is refused, with a time to wait.
    locked = login(client, account["username"], account["password"])
    assert locked.status_code == 429
    assert 0 < int(locked.headers["Retry-After"]) <= settings.LOGIN_FAILURE_WINDOW_SECONDS + 1


def test_a_correct_password_clears_the_count(client):
    account = new_account(client)
    for _ in range(settings.LOGIN_MAX_FAILURES_PER_ACCOUNT - 1):
        assert login(client, account["username"], "wrong-password").status_code == 401
    assert login(client, account["username"], account["password"]).status_code == 200
    # The count started again: four more failures are still allowed.
    for _ in range(settings.LOGIN_MAX_FAILURES_PER_ACCOUNT - 1):
        assert login(client, account["username"], "wrong-password").status_code == 401
    assert login(client, account["username"], account["password"]).status_code == 200


def test_guessing_from_one_address_does_not_lock_the_account_elsewhere(client, monkeypatch):
    # TestClient's connections come from "testclient"; trust it as a proxy so the
    # forwarded address stands for the client.
    from utils import client_address as module

    monkeypatch.setattr(module, "_is_trusted", lambda address: address == "testclient")
    account = new_account(client)
    for _ in range(settings.LOGIN_MAX_FAILURES_PER_ACCOUNT):
        login(client, account["username"], "wrong-password", forwarded_for="203.0.113.9")
    assert login(client, account["username"], account["password"], forwarded_for="203.0.113.9").status_code == 429
    assert login(client, account["username"], account["password"], forwarded_for="198.51.100.4").status_code == 200


def test_one_address_trying_many_accounts_is_stopped(client, monkeypatch):
    from utils import client_address as module

    monkeypatch.setattr(module, "_is_trusted", lambda address: address == "testclient")
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES_PER_ADDRESS", 3)
    address = f"192.0.2.{secrets.randbelow(250) + 1}"
    for _ in range(3):
        assert login(client, f"nobody_{uuid.uuid4().hex[:6]}", "x", forwarded_for=address).status_code == 401
    account = new_account(client)
    assert login(client, account["username"], account["password"], forwarded_for=address).status_code == 429


def test_unknown_and_wrong_passwords_get_the_same_answer(client):
    account = new_account(client)
    unknown = login(client, f"nobody_{uuid.uuid4().hex[:6]}", "whatever")
    wrong = login(client, account["username"], "wrong-password")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_two_first_scans_of_one_device_make_one_asset(client):
    from core.database.repositories.asset_repository import AssetRepository

    name = f"race-{uuid.uuid4().hex[:8]}"

    async def scan_twice():
        from core.services import tenants
        from core.tenancy import set_tenant

        set_tenant(await tenants.default_id())
        repo = AssetRepository()
        defaults = {"asset_type": "workstation", "status": "active", "criticality": "medium"}
        await asyncio.gather(*(repo.record_scan(name, {"os": "Linux"}, defaults) for _ in range(5)))
        return await repo.count({"name": name})

    assert client.portal.call(scan_twice) == 1


def test_renaming_an_asset_to_a_name_in_use_is_refused(client):
    account = new_account(client)
    token = login(client, account["username"], account["password"]).json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}
    first = client.post("/api/v1/assets/", json={"name": f"a-{uuid.uuid4().hex[:8]}", "asset_type": "server"}, headers=auth).json()
    second = client.post("/api/v1/assets/", json={"name": f"b-{uuid.uuid4().hex[:8]}", "asset_type": "server"}, headers=auth).json()

    response = client.put(f"/api/v1/assets/{second['id']}", json={"name": first["name"]}, headers=auth)
    assert response.status_code == 409


class FakeRequest:
    def __init__(self, peer, forwarded=None):
        self.client = type("Client", (), {"host": peer})
        self.headers = {"x-forwarded-for": forwarded} if forwarded else {}


@pytest.mark.parametrize(
    "peer, forwarded, expected",
    [
        # Not from a trusted proxy: the header is ignored, whatever it says.
        ("203.0.113.9", "1.2.3.4", "203.0.113.9"),
        # From the proxy: the address the proxy saw.
        ("10.0.0.2", "198.51.100.4", "198.51.100.4"),
        # A client that sends its own header through the proxy cannot choose its address:
        # the proxy appends the real one, which is read from the right.
        ("10.0.0.2", "1.2.3.4, 198.51.100.4", "198.51.100.4"),
        # Through two trusted proxies.
        ("10.0.0.2", "198.51.100.4, 10.0.0.3", "198.51.100.4"),
    ],
)
def test_client_address(monkeypatch, peer, forwarded, expected):
    from utils import client_address as module

    module._trusted.cache_clear()
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["10.0.0.0/8"])
    assert module.client_address(FakeRequest(peer, forwarded)) == expected
    module._trusted.cache_clear()
