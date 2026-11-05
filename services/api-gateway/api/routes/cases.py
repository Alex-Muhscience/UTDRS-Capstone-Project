"""Cases: related alerts, grouped to be worked once."""
from typing import List, Optional

from urllib.parse import quote

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse

from core.database.repositories.user_repository import UserRepository
from config import settings
from core.models.case import Attachment, Case, CaseEvidence, CaseNote, CaseStatus, CaseUpdate, Priority
from core.models.user import User
from core.services import case_files, case_service
from utils.security import get_current_active_user

router = APIRouter()


def _actor(request: Request) -> dict:
    principal = getattr(request.state, "principal", None) or {}
    return {k: principal.get(k) for k in ("type", "id", "name")}


@router.get("/", response_model=List[Case])
async def list_cases(
    status_: Optional[List[CaseStatus]] = Query(None, alias="status", description="One or more statuses"),
    priority: Optional[Priority] = None,
    owner_id: Optional[str] = Query(None, description="A user id, or 'none' for unassigned cases"),
    open_only: bool = Query(False, description="Only open, investigating and contained cases"),
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
):
    """Cases, most recently active first. The list leaves out each case's timeline."""
    query: dict = {}
    if status_:
        query["status"] = {"$in": status_}
    elif open_only:
        query["status"] = {"$in": case_service.OPEN}
    if priority:
        query["priority"] = priority
    if owner_id:
        query["owner_id"] = None if owner_id == "none" else owner_id
    return await case_service.list_cases(query, limit, skip)


async def _found(case):
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return case


@router.get("/{case_id}", response_model=Case)
async def get_case(case_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """A case with its timeline, and an explanation of it in plain language."""
    return await _found(await case_service.get_case(case_id))


@router.patch("/{case_id}", response_model=Case)
async def update_case(
    update: CaseUpdate, request: Request, case_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """
    Change a case's status, priority, owner or title; each change is added to its
    timeline. Resolving, closing or marking it a false positive does the same to its
    alerts that are still open.
    """
    changes = update.model_dump(exclude_unset=True)
    if changes.get("owner_id") and not await UserRepository().find_by_id(changes["owner_id"]):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="No such user in your organisation")
    return await _found(await case_service.update_case(case_id, changes, _actor(request)))


@router.post("/{case_id}/notes", response_model=Case, status_code=status.HTTP_201_CREATED)
async def add_note(
    note: CaseNote, request: Request, case_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """Add a note to a case's timeline."""
    return await _found(await case_service.add_note(case_id, note.text, _actor(request)))


@router.get("/{case_id}/evidence", response_model=CaseEvidence)
async def case_evidence(case_id: str = Path(...), current_user: User = Depends(get_current_active_user)):
    """The alerts and events behind a case, oldest first, and the entities involved."""
    return await _found(await case_service.evidence(case_id))


@router.post("/{case_id}/attachments", response_model=Attachment, status_code=status.HTTP_201_CREATED)
async def add_attachment(
    request: Request, case_id: str = Path(...), file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)
):
    """
    Attach a file to a case (multipart form, field `file`): up to CASE_ATTACHMENT_MAX_MB,
    twenty a case. Its SHA-256 is recorded, and it is added to the timeline.
    """
    limit = settings.CASE_ATTACHMENT_MAX_MB * 1024 * 1024
    data = await file.read(limit + 1)
    try:
        attachment = await case_files.attach(case_id, file.filename or "file", file.content_type, data, _actor(request))
    except case_files.AttachmentError as e:
        code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE if len(data) > limit else status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(status_code=code, detail=str(e))
    if attachment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    request.state.audit_details = {"file": {"name": attachment["name"], "size": attachment["size"], "sha256": attachment["sha256"]}}
    return attachment


@router.get("/{case_id}/attachments/{attachment_id}", response_class=StreamingResponse,
            responses={200: {"content": {"application/octet-stream": {}}}})
async def download_attachment(
    case_id: str = Path(...), attachment_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """Download a case's file. Always as a download, never shown in the browser."""
    opened = await case_files.open_file(case_id, attachment_id)
    if not opened:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    found, chunks = opened
    name = found.get("filename") or "file"
    ascii_name = name.encode("ascii", "replace").decode().replace("?", "_")
    return StreamingResponse(chunks, media_type="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
        "Content-Length": str(found["length"]),
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-Checksum-SHA256": (found.get("metadata") or {}).get("sha256", ""),
    })


@router.delete("/{case_id}/attachments/{attachment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_attachment(
    request: Request, case_id: str = Path(...), attachment_id: str = Path(...), current_user: User = Depends(get_current_active_user)
):
    """Remove a file from a case: whoever attached it, or an administrator. The timeline keeps that it was there."""
    case = await case_service.get_case(case_id)
    attachment = next((a for a in (case or {}).get("attachments") or [] if a["id"] == attachment_id), None)
    if not attachment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if current_user.role != "admin" and (attachment.get("uploaded_by") or {}).get("id") != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only whoever attached a file, or an administrator, can remove it")
    await case_files.remove(case_id, attachment_id, _actor(request))
    request.state.audit_details = {"file": {"name": attachment["name"], "sha256": attachment["sha256"]}}
