"""
Files attached to cases: screenshots, exported emails, logs, anything an analyst keeps as
evidence.

Files are kept in GridFS (bucket `case_files`), each with its organisation and case, and
listed on the case (`attachments`) with their size and SHA-256, so evidence can be shown to
be unchanged. They are always served as downloads (application/octet-stream, attachment),
never shown in the browser, so an uploaded page or image cannot run in the dashboard. A
case's files go when the case does (retention).
"""
import hashlib
import re
import unicodedata
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from bson import ObjectId
from gridfs import AsyncGridFSBucket, NoFile

from config import settings
from core.database.connection import get_database
from core.tenancy import current_tenant, scoped
from utils.time import utcnow

BUCKET = "case_files"
MAX_PER_CASE = 20


class AttachmentError(ValueError):
    """The file cannot be attached; the message says why, for people."""


def _bucket() -> AsyncGridFSBucket:
    return AsyncGridFSBucket(get_database(), bucket_name=BUCKET)


async def ensure_indexes() -> None:
    await get_database()[f"{BUCKET}.files"].create_index([("metadata.tenant_id", 1), ("metadata.case_id", 1)])


def safe_name(name: str) -> str:
    """A file name that is safe to show and to send back in a header: no paths or control characters."""
    name = unicodedata.normalize("NFC", (name or "").replace("\\", "/").rsplit("/", 1)[-1])
    name = re.sub(r'[\x00-\x1f\x7f"<>|:*?\\]', "_", name).strip(" .")
    return name[:200] or "file"


async def attach(case_id: str, name: str, content_type: Optional[str], data: bytes, actor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Store a file and list it on the case. None when there is no such case."""
    if not ObjectId.is_valid(case_id):
        return None
    cases = scoped(get_database(), "cases")
    case = await cases.find_one({"_id": ObjectId(case_id)}, {"attachments": 1})
    if not case:
        return None
    if len(case.get("attachments") or []) >= MAX_PER_CASE:
        raise AttachmentError(f"A case can have at most {MAX_PER_CASE} files; remove one first")
    limit = settings.CASE_ATTACHMENT_MAX_MB * 1024 * 1024
    if len(data) > limit:
        raise AttachmentError(f"Files can be at most {settings.CASE_ATTACHMENT_MAX_MB} MB")
    if not data:
        raise AttachmentError("The file is empty")
    name = safe_name(name)
    digest = hashlib.sha256(data).hexdigest()
    file_id = await _bucket().upload_from_stream(name, data, metadata={
        "tenant_id": current_tenant(), "case_id": case_id, "content_type": (content_type or "application/octet-stream")[:100], "sha256": digest,
    })
    now = utcnow()
    attachment = {"id": str(file_id), "name": name, "content_type": (content_type or "application/octet-stream")[:100], "size": len(data),
                  "sha256": digest, "uploaded_by": actor, "uploaded_at": now}
    await cases.update_one({"_id": ObjectId(case_id)}, {
        "$push": {"attachments": attachment, "timeline": {"at": now, "kind": "attachment_added", "actor": actor, "text": name,
                                                          "data": {"attachment_id": str(file_id), "size": len(data), "sha256": digest}}},
        "$set": {"updated_at": now},
    })
    return attachment


async def _file(case_id: str, file_id: str) -> Optional[Dict[str, Any]]:
    if not ObjectId.is_valid(file_id):
        return None
    return await get_database()[f"{BUCKET}.files"].find_one(
        {"_id": ObjectId(file_id), "metadata.tenant_id": current_tenant(), "metadata.case_id": case_id}
    )


async def open_file(case_id: str, file_id: str) -> Optional[Tuple[Dict[str, Any], AsyncIterator[bytes]]]:
    """The file's record, and its content in chunks. None when it is not this case's (in this organisation)."""
    found = await _file(case_id, file_id)
    if not found:
        return None
    stream = await _bucket().open_download_stream(found["_id"])

    async def chunks() -> AsyncIterator[bytes]:
        while chunk := await stream.readchunk():
            yield chunk

    return found, chunks()


async def remove(case_id: str, file_id: str, actor: Dict[str, Any]) -> bool:
    found = await _file(case_id, file_id)
    if not found:
        return False
    try:
        await _bucket().delete(found["_id"])
    except NoFile:
        pass
    now = utcnow()
    await scoped(get_database(), "cases").update_one({"_id": ObjectId(case_id)}, {
        "$pull": {"attachments": {"id": file_id}},
        "$push": {"timeline": {"at": now, "kind": "attachment_removed", "actor": actor, "text": found.get("filename"), "data": {"attachment_id": file_id}}},
        "$set": {"updated_at": now},
    })
    return True


async def remove_for_cases(case_ids: List[str]) -> int:
    """Delete every file of these cases (when the cases themselves are deleted)."""
    files = get_database()[f"{BUCKET}.files"]
    removed = 0
    async for found in files.find({"metadata.tenant_id": current_tenant(), "metadata.case_id": {"$in": case_ids}}, {"_id": 1}):
        try:
            await _bucket().delete(found["_id"])
            removed += 1
        except NoFile:
            pass
    return removed
