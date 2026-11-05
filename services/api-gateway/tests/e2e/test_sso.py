"""Single sign-on with OpenID Connect, against a stand-in identity provider."""
import json
import os
import secrets
import time
import uuid
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
ISSUER = "https://idp.example"
CLIENT_ID = "utdrs-client"
REDIRECT = "https://dashboard.example/sso/callback"


class Provider:
    """An OpenID Connect provider: discovery, keys, a token endpoint, and DNS answers."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.codes = {}  # code -> (claims, code_challenge)
        self.txt = {}
        self.tamper = None

    def issue_code(self, nonce, challenge, **claims):
        code = secrets.token_urlsafe(16)
        self.codes[code] = ({"iss": ISSUER, "aud": CLIENT_ID, "sub": claims.pop("sub", uuid.uuid4().hex), "nonce": nonce,
                             "iat": int(time.time()), "exp": int(time.time()) + 300, **claims}, challenge)
        return code

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == "cloudflare-dns.com":
            name = request.url.params["name"]
            return httpx.Response(200, json={"Answer": [{"type": 16, "data": f'"{v}"'} for v in self.txt.get(name, [])]})
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                                             "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/keys"})
        if path == "/keys":
            public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
            return httpx.Response(200, json={"keys": [{**public, "kid": self.kid, "use": "sig", "alg": "RS256"}]})
        if path == "/token":
            form = parse_qs(request.content.decode())
            claims, challenge = self.codes.pop(form["code"][0], (None, None))
            if claims is None or form["client_secret"][0] != "the-secret":
                return httpx.Response(400, json={"error": "invalid_grant"})
            import base64
            import hashlib

            if base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).decode().rstrip("=") != challenge:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "PKCE failed"})
            key = self.key if self.tamper != "other-key" else rsa.generate_private_key(public_exponent=65537, key_size=2048)
            token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": self.kid})
            return httpx.Response(200, json={"id_token": token, "access_token": "x", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


KEY = __import__("base64").b64encode(os.urandom(32)).decode()


@pytest.fixture
def provider(monkeypatch):
    from core.services import sso

    monkeypatch.setattr(settings, "ENCRYPTION_KEY", KEY)  # the client secret is stored encrypted
    fake = Provider()
    monkeypatch.setattr(sso, "transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(settings, "WEBHOOK_ALLOW_PRIVATE_ADDRESSES", True)  # the stand-in has no public address
    return fake


@pytest.fixture
def organisation(client, monkeypatch):
    """A new organisation's administrator, and a domain of its own."""
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"sso_{suffix}", "password": secrets.token_urlsafe(16)}
    domain = f"org{suffix}.example"
    client.post(f"{API}/auth/register", json={**credentials, "email": f"admin@{domain}", "organisation": f"Org {suffix}"})
    token = client.post(f"{API}/auth/login", data=credentials).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, domain, credentials


def set_up(client, provider, admin, domain, **extra):
    saved = client.put(f"{API}/tenants/current/sso", json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "the-secret",
                                                           "domains": [domain], "enabled": True, **extra}, headers=admin)
    assert saved.status_code == 200, saved.text
    record = saved.json()["domains"][0]
    provider.txt[record["record_name"]] = [record["record_value"]]
    verified = client.post(f"{API}/tenants/current/sso/domains/{domain}/verify", headers=admin)
    assert verified.status_code == 200, verified.text
    return verified.json()


def sign_in(client, provider, email, **claims):
    started = client.post(f"{API}/auth/sso/start", json={"email": email, "redirect_uri": REDIRECT})
    assert started.status_code == 200, started.text
    query = parse_qs(urlparse(started.json()["url"]).query)
    assert query["redirect_uri"] == [REDIRECT] and query["code_challenge_method"] == ["S256"]
    code = provider.issue_code(query["nonce"][0], query["code_challenge"][0], email=email, **claims)
    return client.post(f"{API}/auth/sso/callback", json={"code": code, "state": query["state"][0]})


def test_set_up_needs_a_verified_domain(client, provider, organisation):
    admin, domain, _ = organisation
    saved = client.put(f"{API}/tenants/current/sso", json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "the-secret",
                                                           "domains": [domain], "enabled": True}, headers=admin).json()
    assert saved["domains"][0]["verified"] is False
    assert "client_secret" not in saved
    # Not verified: nobody from the domain can use it yet.
    assert client.post(f"{API}/auth/sso/start", json={"email": f"ann@{domain}", "redirect_uri": REDIRECT}).status_code == 400
    refused = client.post(f"{API}/tenants/current/sso/domains/{domain}/verify", headers=admin)
    assert refused.status_code == 409 and "TXT record" in refused.json()["detail"]


def test_a_domain_belongs_to_one_organisation(client, provider, organisation, monkeypatch):
    admin, domain, _ = organisation
    set_up(client, provider, admin, domain)
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"sso_{suffix}", "password": secrets.token_urlsafe(16)}
    client.post(f"{API}/auth/register", json={**credentials, "email": f"x@other{suffix}.example", "organisation": f"Other {suffix}"})
    other = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    record = client.put(f"{API}/tenants/current/sso", json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s",
                                                            "domains": [domain], "enabled": True}, headers=other).json()["domains"][0]
    provider.txt[record["record_name"]] = [record["record_value"]]
    taken = client.post(f"{API}/tenants/current/sso/domains/{domain}/verify", headers=other)
    assert taken.status_code == 409 and "another organisation" in taken.json()["detail"]


def test_people_sign_in_with_their_provider(client, provider, organisation):
    admin, domain, _ = organisation
    set_up(client, provider, admin, domain, auto_provision=True)
    signed_in = sign_in(client, provider, f"ann@{domain}", given_name="Ann", family_name="Analyst")
    assert signed_in.status_code == 200, signed_in.text
    body = signed_in.json()
    assert body["user"]["email"] == f"ann@{domain}" and body["user"]["role"] == "analyst" and body["user"]["email_verified"] is True
    me = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.json()["firstName"] == "Ann"
    # The same person again: the same account.
    again = sign_in(client, provider, f"ann@{domain}").json()
    assert again["user"]["id"] == body["user"]["id"]


def test_without_provisioning_only_existing_accounts_sign_in(client, provider, organisation):
    admin, domain, _ = organisation
    set_up(client, provider, admin, domain)
    assert sign_in(client, provider, f"nobody@{domain}").status_code == 403
    assert sign_in(client, provider, f"admin@{domain}").status_code == 200


def test_a_forged_or_replayed_sign_in_is_refused(client, provider, organisation):
    admin, domain, _ = organisation
    set_up(client, provider, admin, domain)
    provider.tamper = "other-key"
    assert sign_in(client, provider, f"admin@{domain}").status_code == 401
    provider.tamper = None

    started = client.post(f"{API}/auth/sso/start", json={"email": f"admin@{domain}", "redirect_uri": REDIRECT}).json()
    query = parse_qs(urlparse(started["url"]).query)
    wrong_nonce = provider.issue_code("not-the-nonce", query["code_challenge"][0], email=f"admin@{domain}")
    assert client.post(f"{API}/auth/sso/callback", json={"code": wrong_nonce, "state": query["state"][0]}).status_code == 401
    # The state worked once, even though that sign-in failed.
    code = provider.issue_code(query["nonce"][0], query["code_challenge"][0], email=f"admin@{domain}")
    assert client.post(f"{API}/auth/sso/callback", json={"code": code, "state": query["state"][0]}).status_code == 401


def test_an_email_outside_the_domains_is_refused(client, provider, organisation):
    admin, domain, _ = organisation
    set_up(client, provider, admin, domain, auto_provision=True)
    started = client.post(f"{API}/auth/sso/start", json={"email": f"admin@{domain}", "redirect_uri": REDIRECT}).json()
    query = parse_qs(urlparse(started["url"]).query)
    code = provider.issue_code(query["nonce"][0], query["code_challenge"][0], email="mallory@elsewhere.example")
    refused = client.post(f"{API}/auth/sso/callback", json={"code": code, "state": query["state"][0]})
    assert refused.status_code == 401 and "not in one of your organisation's" in refused.json()["detail"]


def test_requiring_sso_leaves_administrators_a_way_in(client, provider, organisation):
    admin, domain, admin_credentials = organisation
    set_up(client, provider, admin, domain, enforce=True, auto_provision=True)
    created = client.post(f"{API}/users/", json={"username": f"bo_{uuid.uuid4().hex[:6]}", "email": f"bo@{domain}", "role": "analyst"}, headers=admin).json()
    refused = client.post(f"{API}/auth/login", data={"username": created["user"]["username"], "password": created["temporary_password"]})
    assert refused.status_code == 403 and "single sign-on" in refused.json()["detail"]
    assert client.post(f"{API}/auth/login", data=admin_credentials).status_code == 200
    assert sign_in(client, provider, f"bo@{domain}").status_code == 200
    assert client.get(f"{API}/auth/config").json()["sso_available"] is True


def test_sso_counts_as_the_second_factor_an_organisation_requires(client, provider, organisation):
    from core.database.connection import get_database

    admin, domain, _ = organisation
    set_up(client, provider, admin, domain, auto_provision=True)
    tenant = client.get(f"{API}/tenants/current", headers=admin).json()["id"]

    async def require():
        from bson import ObjectId

        await get_database()["tenants"].update_one({"_id": ObjectId(tenant)}, {"$set": {"security.require_mfa": True}})

    client.portal.call(require)
    token = sign_in(client, provider, f"cy@{domain}").json()["access_token"]
    me = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["mfa_setup_required"] is False
    assert client.get(f"{API}/alerts/", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_only_administrators_set_it_up(client, provider, organisation):
    admin, domain, _ = organisation
    set_up(client, provider, admin, domain, auto_provision=True)
    analyst = sign_in(client, provider, f"di@{domain}").json()["access_token"]
    assert client.get(f"{API}/tenants/current/sso", headers={"Authorization": f"Bearer {analyst}"}).status_code == 403
