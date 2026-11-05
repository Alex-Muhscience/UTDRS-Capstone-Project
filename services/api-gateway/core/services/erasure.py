"""
Erasing a person: what is done when someone asks for their personal data to be erased,
or an organisation removes a person for good.

The account record stays, nameless and deactivated, so what refers to it (alerts assigned
to it, who did what in a case) still holds together: its username, name and email become
placeholders, and its password, multi-factor authentication, passkeys, SCIM link and
preferences go. Its sessions (with the devices and addresses they recorded), its pending
links (password resets, address confirmations), and its email address on past
notifications go too, and its name is replaced wherever it was copied: in case timelines
and files, response actions, suppressions, verdicts, API keys, webhooks and connections.

The audit log is not changed: each entry is chained to the one before, so changing one
would break the chain that shows the log has not been tampered with. Keeping it is for the
security and accountability of the organisation's records; see docs/legal.
"""
import secrets
from typing import Any, Dict

from bson import ObjectId

from core.database.connection import get_database
from core.tenancy import scoped
from utils.security import get_password_hash
from utils.time import utcnow

# (collection, field holding an actor {type, id, name}) for single actors.
ACTOR_FIELDS = [
    ("actions", "requested_by"), ("actions", "decided_by"), ("actions", "undone_by"),
    ("suppressions", "created_by"), ("alerts", "feedback.by"),
    ("api_keys", "created_by"), ("webhooks", "created_by"), ("connections", "connected_by"),
]
# (collection, array, actor field inside each item) for lists of actors.
ACTOR_LISTS = [("cases", "timeline", "actor"), ("cases", "attachments", "uploaded_by"), ("labels", None, "by")]


class ErasureError(ValueError):
    """The account cannot be erased; the message says why, for people."""


def placeholder(user_id: str) -> Dict[str, str]:
    short = user_id[-8:]
    return {"username": f"erased-{short}", "email": f"erased-{short}@erased.example.com", "name": "Erased person"}


async def erase(user_id: str, admin_id: str) -> Dict[str, Any]:
    """Erase the account's personal data. Returns what was done (counts), for the audit log."""
    if user_id == admin_id:
        raise ErasureError("You cannot erase your own account; ask another administrator")
    users = scoped(get_database(), "users")
    user = await users.find_one({"_id": ObjectId(user_id)}) if ObjectId.is_valid(user_id) else None
    if not user:
        raise LookupError("User not found")
    if user.get("erased_at"):
        raise ErasureError("This account has already been erased")
    if user.get("role") == "admin" and user.get("active", True):
        others = await users.count_documents({"role": "admin", "active": True, "_id": {"$ne": user["_id"]}})
        if not others:
            raise ErasureError("This is the organisation's last active administrator")

    now = utcnow()
    standin = placeholder(user_id)
    old_email = user.get("email")
    await users.update_one({"_id": user["_id"]}, {
        "$set": {"username": standin["username"], "email": standin["email"], "firstName": None, "lastName": None, "active": False,
                 "passwordHash": get_password_hash(secrets.token_urlsafe(32)), "preferences": {}, "email_verified": False,
                 "erased_at": now, "erased_by": admin_id, "updatedAt": now},
        "$unset": {"mfa": "", "passkeys": "", "scim_external_id": "", "registered_self": "", "provisioned_by": ""},
    })

    database = get_database()
    done: Dict[str, int] = {}
    done["sessions"] = (await scoped(database, "sessions").delete_many({"user_id": user_id})).deleted_count
    done["account_links"] = (await database["account_tokens"].delete_many({"user_id": user_id})).deleted_count
    if old_email:
        done["notifications"] = (await scoped(database, "notifications").update_many(
            {"email": old_email}, {"$set": {"email": standin["email"], "text": None}})).modified_count
    renamed = 0
    for collection, field in ACTOR_FIELDS:
        renamed += (await scoped(database, collection).update_many({f"{field}.id": user_id}, {"$set": {f"{field}.name": standin["name"]}})).modified_count
    for collection, array, field in ACTOR_LISTS:
        if array is None:
            renamed += (await scoped(database, collection).update_many({f"{field}.id": user_id}, {"$set": {f"{field}.name": standin["name"]}})).modified_count
            continue
        renamed += (await scoped(database, collection).update_many(
            {f"{array}.{field}.id": user_id}, {"$set": {f"{array}.$[item].{field}.name": standin["name"]}},
            array_filters=[{f"item.{field}.id": user_id}],
        )).modified_count
    done["records_renamed"] = renamed
    return done

