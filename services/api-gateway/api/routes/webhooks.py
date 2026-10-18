"""Webhooks: UTDRS tells your other systems what happens (administrators only)."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status

from api.routes.response import actor_of
from core.models.user import User
from core.models.webhook import Delivery, EventType, SigningSecret, Webhook, WebhookCreate, WebhookUpdate, WebhookWithSecret
from core.services import audit, webhooks
from utils.security import require_admin

router = APIRouter()


def _found(item, what="Webhook"):
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{what} not found")
    return item


def _refused(error: webhooks.WebhookError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


@router.get("/events", response_model=List[EventType])
async def event_types(admin: User = Depends(require_admin)):
    """The events a webhook can be sent."""
    return [{"name": name, "description": text} for name, text in webhooks.EVENTS.items()]


@router.get("/", response_model=List[Webhook])
async def list_webhooks(admin: User = Depends(require_admin)):
    return await webhooks.list_webhooks()


@router.post("/", response_model=WebhookWithSecret, status_code=status.HTTP_201_CREATED)
async def create_webhook(body: WebhookCreate, request: Request, admin: User = Depends(require_admin)):
    """
    Send events to an HTTPS endpoint. The response holds the signing secret, shown only
    this once: check each request's `UTDRS-Signature` header with it.
    """
    try:
        webhook = await webhooks.create(body.model_dump(), actor_of(request))
    except webhooks.WebhookError as e:
        raise _refused(e)
    audit.created(request, "webhook", str(webhook["_id"]), webhook["name"])
    return webhook


@router.patch("/{webhook_id}", response_model=Webhook)
async def update_webhook(body: WebhookUpdate, webhook_id: str = Path(...), admin: User = Depends(require_admin)):
    try:
        return _found(await webhooks.update(webhook_id, body.model_dump(exclude_none=True)))
    except webhooks.WebhookError as e:
        raise _refused(e)


@router.post("/{webhook_id}/rotate-secret", response_model=SigningSecret)
async def rotate_secret(webhook_id: str = Path(...), admin: User = Depends(require_admin)):
    """A new signing secret, shown only this once; the old one stops being used at once."""
    return {"signing_secret": _found(await webhooks.rotate_secret(webhook_id))}


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(webhook_id: str = Path(...), admin: User = Depends(require_admin)):
    if not await webhooks.delete(webhook_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")


@router.post("/{webhook_id}/test", status_code=status.HTTP_202_ACCEPTED)
async def test_webhook(webhook_id: str = Path(...), admin: User = Depends(require_admin)):
    """Queue a `ping` event to this webhook (whatever events it wants); see the delivery log for how it went."""
    _found(await webhooks.get(webhook_id))
    await webhooks.emit("ping", {"message": "A test from UTDRS"}, only=webhook_id)
    return {"queued": True}


@router.get("/{webhook_id}/deliveries", response_model=List[Delivery])
async def deliveries(webhook_id: str = Path(...), admin: User = Depends(require_admin)):
    """The latest deliveries, newest first, with each attempt's outcome."""
    _found(await webhooks.get(webhook_id))
    return await webhooks.deliveries_of(webhook_id)


@router.post("/deliveries/{delivery_id}/redeliver", response_model=Delivery)
async def redeliver(delivery_id: str = Path(...), admin: User = Depends(require_admin)):
    """Send a delivered or failed delivery again (same id, so receivers can tell it is a repeat)."""
    return _found(await webhooks.redeliver(delivery_id), "Delivery")
