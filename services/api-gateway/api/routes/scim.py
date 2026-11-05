"""
SCIM 2.0 for identity providers: /api/v1/scim/v2 (core/services/scim.py says how it is used).

Users only. A user's `userName` is their UTDRS username (usually their email address);
`name.givenName` and `name.familyName`, the primary `emails` value, `active` and
`externalId` are kept. Answers and errors use SCIM's JSON (application/scim+json).
"""
import re
import secrets
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from core.database.connection import get_database
from core.database.repositories.user_repository import UserRepository
from core.models.user import UserCreate
from core.services import audit, scim, sessions
from config import settings
from core.tenancy import scoped, set_tenant

router = APIRouter()

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
MEDIA = "application/scim+json"
MAX_PAGE = 200
ACTOR = {"type": "scim", "name": "identity provider (SCIM)"}


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: Optional[str] = None):
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type


def _answer(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(content=body, status_code=status, media_type=MEDIA)


def _error(error: ScimError) -> JSONResponse:
    body = {"schemas": [ERROR_SCHEMA], "status": str(error.status), "detail": error.detail}
    if error.scim_type:
        body["scimType"] = error.scim_type
    return _answer(body, error.status)


async def scim_organisation(request: Request) -> str:
    """The organisation named by the bearer SCIM token; refuses anything else."""
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    tenant = await scim.tenant_for(token) if token else None
    if not tenant:
        raise ScimError(401, "A valid SCIM token is needed")
    set_tenant(tenant)
    request.state.principal = ACTOR
    return tenant


def _base(request: Request) -> str:
    return str(request.base_url).rstrip("/") + f"{settings.API_PREFIX}/scim/v2"


def _resource(user: Dict[str, Any], request: Request) -> Dict[str, Any]:
    user_id = str(user["_id"])
    resource = {
        "schemas": [USER_SCHEMA],
        "id": user_id,
        "userName": user["username"],
        "name": {k: v for k, v in (("givenName", user.get("firstName")), ("familyName", user.get("lastName"))) if v},
        "emails": [{"value": user["email"], "primary": True, "type": "work"}] if user.get("email") else [],
        "active": bool(user.get("active", True)),
        "meta": {"resourceType": "User", "created": _iso(user.get("createdAt")), "lastModified": _iso(user.get("updatedAt")),
                 "location": f"{_base(request)}/Users/{user_id}"},
    }
    if user.get("scim_external_id"):
        resource["externalId"] = user["scim_external_id"]
    return resource


def _iso(value) -> Optional[str]:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _users():
    return scoped(get_database(), "users")


async def _find(user_id: str) -> Dict[str, Any]:
    user = await _users().find_one({"_id": ObjectId(user_id)}) if ObjectId.is_valid(user_id) else None
    if not user:
        raise ScimError(404, f"No user {user_id}")
    return user


def _primary_email(body: Dict[str, Any]) -> Optional[str]:
    emails = body.get("emails") or []
    chosen = next((e for e in emails if e.get("primary")), emails[0] if emails else None)
    value = (chosen or {}).get("value")
    if not value and "@" in str(body.get("userName", "")):
        value = body["userName"]
    return str(value).strip().lower() if value else None


async def _guard_last_admin(user: Dict[str, Any]) -> None:
    if user.get("role") != "admin" or not user.get("active", True):
        return
    others = await _users().count_documents({"role": "admin", "active": True, "_id": {"$ne": user["_id"]}})
    if not others:
        raise ScimError(400, "This is the organisation's last active administrator: it cannot be deactivated through SCIM", "mutability")


async def _apply(user: Dict[str, Any], changes: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Change an account; deactivating it ends its sessions."""
    fields: Dict[str, Any] = {}
    if "active" in changes and changes["active"] is not None:
        active = bool(changes["active"])
        if not active:
            await _guard_last_admin(user)
        fields["active"] = active
    for key in ("firstName", "lastName", "scim_external_id"):
        if key in changes:
            fields[key] = changes[key]
    if changes.get("email") and changes["email"] != user.get("email"):
        taken = await UserRepository().find_by_email(changes["email"])
        if taken and taken["_id"] != user["_id"]:
            raise ScimError(409, f"{changes['email']} is already another account's", "uniqueness")
        fields["email"], fields["email_verified"] = changes["email"], True
    if changes.get("userName") and changes["userName"] != user["username"]:
        taken = await UserRepository().find_by_username(changes["userName"])
        if taken and taken["_id"] != user["_id"]:
            raise ScimError(409, f"{changes['userName']} is already taken", "uniqueness")
        fields["username"] = changes["userName"]
    if fields:
        from utils.time import utcnow

        fields["updatedAt"] = utcnow()
        await _users().update_one({"_id": user["_id"]}, {"$set": fields})
        if fields.get("active") is False and user.get("active", True):
            await sessions.end_all(str(user["_id"]), "This account has been deactivated")
        await audit.record("scim.user_updated", request, actor=ACTOR, target={"type": "user", "id": str(user["_id"]), "name": user["username"]},
                           details={"fields": sorted(k for k in fields if k != "updatedAt")})
    return await _find(str(user["_id"]))


def _from_resource(body: Dict[str, Any]) -> Dict[str, Any]:
    name = body.get("name") or {}
    changes: Dict[str, Any] = {}
    if "userName" in body:
        changes["userName"] = str(body["userName"]).strip()
    if "active" in body:
        changes["active"] = body["active"]
    if "givenName" in name:
        changes["firstName"] = name["givenName"]
    if "familyName" in name:
        changes["lastName"] = name["familyName"]
    if "externalId" in body:
        changes["scim_external_id"] = body["externalId"]
    email = _primary_email(body) if "emails" in body else None
    if email:
        changes["email"] = email
    return changes


def _from_patch(operations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Entra ID's and Okta's PATCH operations, as changes to an account."""
    changes: Dict[str, Any] = {}
    for operation in operations:
        op = str(operation.get("op", "")).lower()
        if op not in ("add", "replace"):
            raise ScimError(400, f"The {op!r} operation is not supported", "invalidSyntax")
        path, value = operation.get("path"), operation.get("value")
        if not path:  # the value is a partial resource
            changes.update(_from_resource(value or {}))
            continue
        path = str(path)
        if path == "active":
            changes["active"] = value if isinstance(value, bool) else str(value).lower() == "true"
        elif path == "userName":
            changes["userName"] = str(value)
        elif path == "name.givenName":
            changes["firstName"] = value
        elif path == "name.familyName":
            changes["lastName"] = value
        elif path == "externalId":
            changes["scim_external_id"] = value
        elif path.startswith("emails"):
            changes["email"] = str(value[0]["value"] if isinstance(value, list) else value).lower()
        # Other attributes (displayName, title, ...) are not kept: ignored, as SCIM allows.
    return changes


# ---------------------------------------------------------------------------- Discovery

@router.get("/ServiceProviderConfig")
async def service_provider_config(request: Request):
    return _answer({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_PAGE}, "changePassword": {"supported": False},
        "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "SCIM token", "description": "The organisation's SCIM token, made in UTDRS", "primary": True}],
    })


@router.get("/ResourceTypes")
async def resource_types(request: Request):
    return _answer({"schemas": [LIST_SCHEMA], "totalResults": 1, "Resources": [
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/Users", "schema": USER_SCHEMA},
    ]})


@router.get("/Schemas")
async def schemas(request: Request):
    attributes = [{"name": n, "type": t, "multiValued": m, "required": r} for n, t, m, r in
                  (("userName", "string", False, True), ("name", "complex", False, False), ("emails", "complex", True, False),
                   ("active", "boolean", False, False), ("externalId", "string", False, False))]
    return _answer({"schemas": [LIST_SCHEMA], "totalResults": 1, "Resources": [{"id": USER_SCHEMA, "name": "User", "attributes": attributes}]})


# ---------------------------------------------------------------------------- Users

FILTER = re.compile(r'^\s*(userName|externalId|emails(?:\.value)?|emails\[type eq "work"\]\.value)\s+eq\s+"([^"]*)"\s*$', re.IGNORECASE)


@router.get("/Users")
async def list_users(request: Request, filter: Optional[str] = None, startIndex: int = 1, count: int = 100):
    try:
        await scim_organisation(request)
        query: Dict[str, Any] = {}
        if filter:
            match = FILTER.match(filter)
            if not match:
                raise ScimError(400, "Only filters of the form userName eq \"...\", externalId eq \"...\" or emails eq \"...\" are supported", "invalidFilter")
            attribute, value = match.group(1).lower(), match.group(2)
            field = {"username": "username", "externalid": "scim_external_id"}.get(attribute, "email")
            query[field] = value.lower() if field == "email" else value
        start, count = max(1, startIndex), max(0, min(count, MAX_PAGE))
        total = await _users().count_documents(query)
        found = await _users().find(query).sort("_id", 1).skip(start - 1).limit(count).to_list(count)
        return _answer({"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start, "itemsPerPage": len(found),
                        "Resources": [_resource(u, request) for u in found]})
    except ScimError as e:
        return _error(e)


@router.get("/Users/{user_id}")
async def get_user(user_id: str, request: Request):
    try:
        await scim_organisation(request)
        return _answer(_resource(await _find(user_id), request))
    except ScimError as e:
        return _error(e)


@router.post("/Users")
async def create_user(request: Request):
    try:
        await scim_organisation(request)
        body = await request.json()
        changes = _from_resource(body)
        username = changes.get("userName")
        email = changes.get("email")
        if not username or not email:
            raise ScimError(400, "userName and an email address are needed", "invalidValue")
        repo = UserRepository()
        if await repo.find_by_username(username) or await repo.find_by_email(email):
            raise ScimError(409, f"{username} already has an account", "uniqueness")
        account = UserCreate(username=username, email=email, password=secrets.token_urlsafe(32), role="analyst",
                             active=bool(changes.get("active", True)), firstName=changes.get("firstName"), lastName=changes.get("lastName"))
        user_id = await repo.create_user(account, email_verified=True, provisioned_by="scim", scim_external_id=changes.get("scim_external_id"))
        await audit.record("scim.user_created", request, actor=ACTOR, target={"type": "user", "id": user_id, "name": username})
        response = _answer(_resource(await _find(user_id), request), 201)
        response.headers["Location"] = f"{_base(request)}/Users/{user_id}"
        return response
    except ScimError as e:
        return _error(e)
    except ValueError as e:
        return _error(ScimError(400, f"Not valid: {e}", "invalidValue"))


@router.put("/Users/{user_id}")
async def replace_user(user_id: str, request: Request):
    try:
        await scim_organisation(request)
        user = await _find(user_id)
        return _answer(_resource(await _apply(user, _from_resource(await request.json()), request), request))
    except ScimError as e:
        return _error(e)


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request):
    try:
        await scim_organisation(request)
        body = await request.json()
        if PATCH_SCHEMA not in (body.get("schemas") or []):
            raise ScimError(400, "A PatchOp message is needed", "invalidSyntax")
        user = await _find(user_id)
        return _answer(_resource(await _apply(user, _from_patch(body.get("Operations") or []), request), request))
    except ScimError as e:
        return _error(e)


@router.delete("/Users/{user_id}")
async def delete_user(user_id: str, request: Request):
    """Removing someone deactivates their account (their history in UTDRS stays) and ends their sessions."""
    try:
        await scim_organisation(request)
        user = await _find(user_id)
        await _apply(user, {"active": False}, request)
        return Response(status_code=204)
    except ScimError as e:
        return _error(e)


@router.get("/Groups")
async def list_groups(request: Request):
    """Groups are not supported; an empty list, so identity providers that ask carry on."""
    try:
        await scim_organisation(request)
        return _answer({"schemas": [LIST_SCHEMA], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": []})
    except ScimError as e:
        return _error(e)

