"""
Passkeys (WebAuthn): signing in with a device's fingerprint, face or PIN instead of a
password, using a key that never leaves the device.

A person adds passkeys while signed in, and signs in with one from then on: the browser
offers the passkeys it has for this site (discoverable credentials), the device checks it
is them (user verification is required), and signs a one-time challenge. The signature is
checked against the public key kept when the passkey was added, for this site only
(WEBAUTHN_RP_ID, and the dashboard's origin), so a passkey cannot be phished: a look-alike
site gets nothing it can use. A passkey sign-in therefore counts as multi-factor.

Each challenge works once, within CHALLENGE_LIFETIME. The authenticator's signature counter
must go up (when it keeps one): a counter that goes back means the key was copied.
"""
import base64
import secrets
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bson import ObjectId
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from config import settings
from core.database.connection import get_database
from utils.time import utcnow

CHALLENGES = "webauthn_challenges"
CHALLENGE_LIFETIME = timedelta(minutes=5)
MAX_PASSKEYS = 10


class PasskeyError(ValueError):
    """The passkey cannot be added or used; the message says why, for people."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rp_id() -> str:
    """The site passkeys belong to: WEBAUTHN_RP_ID, or the dashboard's host."""
    return settings.WEBAUTHN_RP_ID or (urlparse(settings.DASHBOARD_URL).hostname or "localhost")


def origins() -> List[str]:
    """Where sign-ins may come from: WEBAUTHN_ORIGINS, or the dashboard's origin."""
    if settings.WEBAUTHN_ORIGINS:
        return settings.WEBAUTHN_ORIGINS
    parsed = urlparse(settings.DASHBOARD_URL)
    return [f"{parsed.scheme}://{parsed.netloc}"]


async def ensure_indexes() -> None:
    await get_database()[CHALLENGES].create_index("expires_at", expireAfterSeconds=0)
    # A passkey signs in one account: found by its id, before anyone is known.
    # Only where a passkey exists: an emptied list would otherwise count as a value.
    await get_database()["users"].create_index(
        "passkeys.id", unique=True, name="passkey_id_unique", partialFilterExpression={"passkeys.id": {"$exists": True}}
    )


async def _new_challenge(purpose: str, user_id: Optional[str] = None) -> bytes:
    challenge = secrets.token_bytes(32)
    await get_database()[CHALLENGES].insert_one({
        "_id": _b64(challenge), "purpose": purpose, "user_id": user_id, "expires_at": utcnow() + CHALLENGE_LIFETIME,
    })
    return challenge


async def _spend_challenge(client_data_challenge: str, purpose: str, user_id: Optional[str] = None) -> bytes:
    """The challenge the browser signed, if we issued it for this, and it is unused and current."""
    found = await get_database()[CHALLENGES].find_one_and_delete({"_id": client_data_challenge, "purpose": purpose})
    if not found or (user_id and found.get("user_id") != user_id):
        raise PasskeyError("This passkey request has expired or was already used; try again")
    expires = found["expires_at"]
    if expires.replace(tzinfo=None) < utcnow().replace(tzinfo=None):
        raise PasskeyError("This passkey request has expired; try again")
    return _unb64(client_data_challenge)


def _client_challenge(credential: Dict[str, Any]) -> str:
    """The challenge inside the browser's response (clientDataJSON), to find ours."""
    import json

    try:
        client_data = json.loads(_unb64(credential["response"]["clientDataJSON"]))
        return str(client_data["challenge"])
    except (KeyError, TypeError, ValueError):
        raise PasskeyError("That is not a passkey response")


# ---------------------------------------------------------------------------- Adding

async def registration_options(user: Dict[str, Any]) -> str:
    """What the browser needs to create a passkey for `user` (JSON for navigator.credentials.create)."""
    existing = user.get("passkeys") or []
    if len(existing) >= MAX_PASSKEYS:
        raise PasskeyError(f"You can have at most {MAX_PASSKEYS} passkeys; remove one first")
    user_id = str(user["_id"])
    options = generate_registration_options(
        rp_id=rp_id(), rp_name="UTDRS", user_name=user.get("email") or user["username"],
        user_id=user_id.encode(), user_display_name=user.get("username"),
        challenge=await _new_challenge("register", user_id),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=_unb64(p["id"])) for p in existing],
    )
    return options_to_json(options)


async def register(user: Dict[str, Any], credential: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Check the new passkey and keep its public key. Returns what is shown about it."""
    user_id = str(user["_id"])
    challenge = await _spend_challenge(_client_challenge(credential), "register", user_id)
    try:
        verified = verify_registration_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=rp_id(), expected_origin=origins(),
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as e:
        raise PasskeyError(f"The passkey could not be checked: {e}")
    now = utcnow()
    passkey = {
        "id": _b64(verified.credential_id), "public_key": _b64(verified.credential_public_key), "sign_count": verified.sign_count,
        "name": (name or "Passkey").strip()[:60] or "Passkey", "created_at": now, "last_used_at": None,
        "transports": (credential.get("response") or {}).get("transports") or [],
        "backed_up": bool(getattr(verified, "credential_backed_up", False)),
    }
    try:
        await get_database()["users"].update_one({"_id": ObjectId(user_id)}, {"$push": {"passkeys": passkey}})
    except Exception as e:
        if "duplicate key" in str(e).lower():
            raise PasskeyError("That passkey is already in use")
        raise
    return public(passkey)


def public(passkey: Dict[str, Any]) -> Dict[str, Any]:
    return {k: passkey.get(k) for k in ("id", "name", "created_at", "last_used_at", "backed_up")}


async def remove(user_id: str, passkey_id: str) -> bool:
    result = await get_database()["users"].update_one({"_id": ObjectId(user_id)}, {"$pull": {"passkeys": {"id": passkey_id}}})
    return bool(result.modified_count)


# ---------------------------------------------------------------------------- Signing in

async def authentication_options() -> str:
    """What the browser needs to sign in with any passkey it has for this site."""
    options = generate_authentication_options(
        rp_id=rp_id(), challenge=await _new_challenge("login"), user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(options)


async def authenticate(credential: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Check a passkey sign-in. Returns the account and the passkey used."""
    challenge = await _spend_challenge(_client_challenge(credential), "login")
    passkey_id = str(credential.get("id") or credential.get("rawId") or "")
    user = await get_database()["users"].find_one({"passkeys.id": passkey_id})
    if not user:
        raise PasskeyError("This passkey is not known to UTDRS: it may have been removed")
    passkey = next(p for p in user["passkeys"] if p["id"] == passkey_id)
    try:
        verified = verify_authentication_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=rp_id(), expected_origin=origins(),
            credential_public_key=_unb64(passkey["public_key"]), credential_current_sign_count=passkey.get("sign_count") or 0,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as e:
        raise PasskeyError(f"The passkey sign-in could not be checked: {e}")
    await get_database()["users"].update_one(
        {"_id": user["_id"], "passkeys.id": passkey_id},
        {"$set": {"passkeys.$.sign_count": verified.new_sign_count, "passkeys.$.last_used_at": utcnow()}},
    )
    return user, passkey
