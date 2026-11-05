"""
Single sign-on with OpenID Connect: people sign in with their organisation's identity
provider (Microsoft Entra ID, Google, Okta, ...) instead of a UTDRS password.

An administrator sets up the provider (its issuer, and a client id and secret registered
there) and the email domains it signs in. A domain must be shown to be the organisation's
(a DNS TXT record) before it is used: otherwise another organisation could claim it and
send its people to a provider of its choosing.

Signing in: the person gives their work email; its domain names the organisation; they
are sent to the provider (authorization code flow, with PKCE, state and nonce); the
provider sends them back with a code, which the gateway exchanges for an ID token. The
token's signature (the provider's published keys), issuer, audience, expiry and nonce are
checked, and its email must be in one of the organisation's domains. That person's
account signs in; with `auto_provision`, someone without one gets an analyst account.

With `enforce`, the organisation's people sign in only with SSO; administrators keep
their password (with MFA), so a broken provider cannot lock everyone out.
"""
import base64
import hashlib
import secrets
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx
import jwt
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from config import settings
from core.database.connection import get_database
from core.services.webhooks import WebhookError, check_url
from core.tenancy import current_tenant
from utils import crypto
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

CONFIGS = "sso_configs"
LOGINS = "sso_logins"
LOGIN_LIFETIME = timedelta(minutes=10)
TIMEOUT = 10.0
SIGNING_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
VERIFICATION_RECORD = "_utdrs-verification"

# Tests replace this to answer for the provider and for DNS.
transport: Optional[httpx.AsyncBaseTransport] = None


class SsoError(ValueError):
    """Single sign-on cannot go ahead; the message says why, for people."""


def _configs():
    return get_database()[CONFIGS]


async def ensure_indexes() -> None:
    await _configs().create_index("tenant_id", unique=True)
    # A verified domain belongs to one organisation.
    await _configs().create_index("verified_domains", unique=True, sparse=True)
    await get_database()[LOGINS].create_index("expires_at", expireAfterSeconds=0)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=TIMEOUT, transport=transport, follow_redirects=False)


def _context(tenant_id: str) -> str:
    return f"sso:{tenant_id}"


# ---------------------------------------------------------------------------- Settings

def public(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The settings as administrators see them: never the secret."""
    if not config:
        return {"configured": False, "encryption_available": crypto.available()}
    return {
        "configured": True,
        "issuer": config["issuer"],
        "client_id": config["client_id"],
        "domains": [{"domain": d, "verified": d in (config.get("verified_domains") or []),
                     "record_name": f"{VERIFICATION_RECORD}.{d}", "record_value": _record_value(config, d)} for d in config.get("domains") or []],
        "enabled": config.get("enabled", False),
        "enforce": config.get("enforce", False),
        "auto_provision": config.get("auto_provision", False),
        "updated_at": config.get("updated_at"),
        "encryption_available": crypto.available(),
    }


def _record_value(config: Dict[str, Any], domain: str) -> str:
    digest = hashlib.sha256(f"{config['verification_secret']}:{domain}".encode()).hexdigest()[:32]
    return f"utdrs-verification={digest}"


async def get_config(tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return await _configs().find_one({"tenant_id": tenant_id or current_tenant()})


async def discover(issuer: str) -> Dict[str, Any]:
    """The provider's OpenID configuration, checked: it must name itself as `issuer`."""
    issuer = issuer.rstrip("/")
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        await check_url(url)
    except WebhookError as e:
        raise SsoError(f"The issuer must be a public HTTPS address: {e}")
    try:
        async with _client() as client:
            response = await client.get(url)
        response.raise_for_status()
        found = response.json()
    except (httpx.HTTPError, ValueError) as e:
        raise SsoError(f"Could not read the provider's configuration at {url}: {e.__class__.__name__}")
    if str(found.get("issuer", "")).rstrip("/") != issuer:
        raise SsoError(f"The provider calls itself {found.get('issuer')!r}, not {issuer!r}: use that as the issuer")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(found.get(field, "")).startswith("https://"):
            raise SsoError(f"The provider's configuration has no HTTPS {field}")
    return found


def _domain(value: str) -> str:
    domain = value.strip().lower().lstrip("@")
    if not domain or "." not in domain or any(c in domain for c in "/:@ "):
        raise SsoError(f"{value!r} is not a domain")
    return domain


async def save(changes: Dict[str, Any]) -> Dict[str, Any]:
    """Set up or change the organisation's provider. The secret, when given, is stored encrypted."""
    tenant = current_tenant()
    existing = await get_config(tenant) or {}
    issuer = (changes.get("issuer") or existing.get("issuer") or "").rstrip("/")
    client_id = changes.get("client_id") or existing.get("client_id")
    if not issuer or not client_id:
        raise SsoError("Give the provider's issuer and the client id registered there")
    if changes.get("client_secret") is None and not existing.get("client_secret"):
        raise SsoError("Give the client secret registered at the provider")
    if changes.get("client_secret") and not crypto.available():
        raise SsoError("Single sign-on needs ENCRYPTION_KEY set on the gateway, to keep the client secret")
    if issuer != existing.get("issuer"):
        await discover(issuer)
    domains = sorted({_domain(d) for d in changes.get("domains", existing.get("domains") or [])})
    if not domains:
        raise SsoError("Name at least one email domain that signs in with this provider")
    fields: Dict[str, Any] = {
        "tenant_id": tenant, "issuer": issuer, "client_id": client_id, "domains": domains,
        # A domain removed is no longer verified; one kept stays verified.
        "verified_domains": [d for d in existing.get("verified_domains") or [] if d in domains],
        "enabled": changes.get("enabled", existing.get("enabled", False)),
        "enforce": changes.get("enforce", existing.get("enforce", False)),
        "auto_provision": changes.get("auto_provision", existing.get("auto_provision", False)),
        "verification_secret": existing.get("verification_secret") or secrets.token_hex(16),
        "updated_at": utcnow(),
    }
    if changes.get("client_secret"):
        fields["client_secret"] = crypto.encrypt(changes["client_secret"], _context(tenant))
    if fields["enforce"] and not fields["enabled"]:
        raise SsoError("Turn single sign-on on before requiring it")
    update: Dict[str, Any] = {"$set": fields}
    if not fields["verified_domains"]:
        # Absent rather than empty: an empty list would count as a value in the unique index.
        del fields["verified_domains"]
        update["$unset"] = {"verified_domains": ""}
    await _configs().update_one({"tenant_id": tenant}, update, upsert=True)
    return await get_config(tenant)


async def remove() -> bool:
    return bool((await _configs().delete_one({"tenant_id": current_tenant()})).deleted_count)


async def _txt_records(name: str) -> List[str]:
    """TXT records for `name`, by DNS over HTTPS."""
    async with _client() as client:
        response = await client.get(settings.SSO_DNS_RESOLVER, params={"name": name, "type": "TXT"}, headers={"Accept": "application/dns-json"})
    response.raise_for_status()
    return [str(answer.get("data", "")).strip('"').replace('" "', "") for answer in response.json().get("Answer") or [] if answer.get("type") == 16]


async def verify_domain(domain: str) -> Dict[str, Any]:
    """Check the domain's TXT record, and mark it the organisation's."""
    config = await get_config()
    domain = _domain(domain)
    if not config or domain not in (config.get("domains") or []):
        raise SsoError(f"Add {domain} to the single sign-on domains first")
    expected = _record_value(config, domain)
    try:
        records = await _txt_records(f"{VERIFICATION_RECORD}.{domain}")
    except (httpx.HTTPError, ValueError) as e:
        raise SsoError(f"Could not look up DNS records: {e.__class__.__name__}")
    if expected not in records:
        raise SsoError(f"No TXT record {VERIFICATION_RECORD}.{domain} with the value {expected} yet. DNS changes can take a while to appear.")
    try:
        await _configs().update_one({"_id": config["_id"]}, {"$addToSet": {"verified_domains": domain}})
    except DuplicateKeyError:
        raise SsoError(f"{domain} is already another organisation's")
    return await get_config()


# ---------------------------------------------------------------------------- Signing in

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


async def config_for_email(email: str) -> Optional[Dict[str, Any]]:
    """The enabled SSO set-up of the organisation that has verified this email's domain."""
    domain = email.strip().lower().rsplit("@", 1)[-1] if "@" in email else ""
    if not domain:
        return None
    return await _configs().find_one({"verified_domains": domain, "enabled": True})


async def start(email: str, redirect_uri: str) -> str:
    """Where to send the person to sign in with their organisation's provider."""
    config = await config_for_email(email)
    if not config:
        raise SsoError("Single sign-on is not set up for that email's domain; sign in with your password")
    found = await discover(config["issuer"])
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    await get_database()[LOGINS].insert_one({
        "_id": hashlib.sha256(state.encode()).hexdigest(), "tenant_id": config["tenant_id"], "nonce": nonce, "verifier": verifier,
        "redirect_uri": redirect_uri, "login_hint": email, "expires_at": utcnow() + LOGIN_LIFETIME,
    })
    query = {
        "response_type": "code", "client_id": config["client_id"], "redirect_uri": redirect_uri, "scope": "openid email profile",
        "state": state, "nonce": nonce, "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256", "login_hint": email,
    }
    return f"{found['authorization_endpoint']}?{urlencode(query)}"


async def finish(code: str, state: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    The provider sent the person back: check everything, and return the organisation's
    settings and the ID token's claims (with `email` set from the token).
    """
    login = await get_database()[LOGINS].find_one_and_delete({"_id": hashlib.sha256(state.encode()).hexdigest()})
    if not login or login["expires_at"].replace(tzinfo=None) < utcnow().replace(tzinfo=None):
        raise SsoError("This sign-in has expired or was already used; start again")
    config = await get_config(login["tenant_id"])
    if not config or not config.get("enabled"):
        raise SsoError("Single sign-on is no longer set up for your organisation")
    found = await discover(config["issuer"])
    secret = crypto.decrypt(config["client_secret"], _context(config["tenant_id"]))
    try:
        async with _client() as client:
            response = await client.post(found["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": login["redirect_uri"],
                "client_id": config["client_id"], "client_secret": secret, "code_verifier": login["verifier"],
            }, headers={"Accept": "application/json"})
            if response.is_error:
                try:
                    reason = response.json().get("error_description") or response.json().get("error") or ""
                except ValueError:
                    reason = ""
                raise SsoError(f"The provider refused the sign-in ({response.status_code}) {reason}".strip())
            id_token = response.json().get("id_token")
            if not id_token:
                raise SsoError("The provider sent no ID token")
            keys = (await client.get(found["jwks_uri"])).raise_for_status().json()
    except SsoError:
        raise
    except (httpx.HTTPError, ValueError) as e:
        raise SsoError(f"Could not reach the provider: {e.__class__.__name__}")
    claims = _verified_claims(id_token, keys, config, found, login["nonce"])
    return config, claims


def _verified_claims(id_token: str, keys: Dict[str, Any], config: Dict[str, Any], found: Dict[str, Any], nonce: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise SsoError("The provider's ID token is not readable")
    algorithm = header.get("alg")
    if algorithm not in SIGNING_ALGORITHMS:
        raise SsoError(f"The ID token is signed with {algorithm}, which UTDRS does not accept")
    candidates = [k for k in keys.get("keys") or [] if not header.get("kid") or k.get("kid") == header.get("kid")]
    if not candidates:
        raise SsoError("The ID token is signed with a key the provider does not publish")
    try:
        key = jwt.PyJWK.from_dict(candidates[0], algorithm=algorithm)
        claims = jwt.decode(id_token, key.key, algorithms=[algorithm], audience=config["client_id"], issuer=found["issuer"],
                            options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=60)
    except jwt.PyJWTError as e:
        raise SsoError(f"The ID token is not valid: {e}")
    if claims.get("nonce") != nonce:
        raise SsoError("The ID token is not for this sign-in")
    # Google and most providers send `email`; Entra ID may send only the user's sign-in name.
    email = str(claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "").strip().lower()
    if "@" not in email:
        raise SsoError("The provider did not say who signed in (no email in the ID token): add the email claim")
    if claims.get("email_verified") is False:
        raise SsoError("The provider says this email address is not verified")
    if email.rsplit("@", 1)[1] not in (config.get("verified_domains") or []):
        raise SsoError(f"{email} is not in one of your organisation's single sign-on domains")
    return {**claims, "email": email}


async def any_enabled() -> bool:
    return await _configs().find_one({"enabled": True, "verified_domains.0": {"$exists": True}}, {"_id": 1}) is not None


async def enforced_for(user: Dict[str, Any]) -> bool:
    """Whether this person must sign in with SSO (administrators never must: they are the way back in)."""
    if user.get("role") == "admin":
        return False
    config = await _configs().find_one({"tenant_id": user["tenant_id"], "enabled": True, "enforce": True}, {"_id": 1})
    return config is not None
