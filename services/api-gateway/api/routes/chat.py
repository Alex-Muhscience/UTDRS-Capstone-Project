"""Slack and Microsoft Teams channels (administrators), and Slack's clicks on Approve and Reject."""
from datetime import datetime
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, Field

from core.models.user import User
from core.services import audit, chat
from utils.security import get_current_active_user, require_admin

router = APIRouter()


class ChatEvent(BaseModel):
    name: str
    description: str


class ChatChannel(BaseModel):
    id: str
    name: str
    # slack_webhook: messages; slack_app: messages, and approving from Slack; teams: Adaptive Cards.
    kind: str
    events: List[str]
    min_alert_severity: str = "high"
    enabled: bool = True
    slack_channel: Optional[str] = None
    # ok, failing, or nothing sent yet.
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    last_sent_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    # For a Slack app: the Request URL to give Slack under Interactivity & Shortcuts.
    interactions_url: Optional[str] = None


class NewChatChannel(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["slack_webhook", "slack_app", "teams"]
    events: List[str] = Field(min_length=1, max_length=20)
    min_alert_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    # Slack webhook or Teams Workflows: the URL (kept encrypted; it is a credential).
    webhook_url: Optional[str] = Field(None, max_length=2000)
    # Slack app: its bot token (xoxb-...), its signing secret, and the channel's id (C...).
    bot_token: Optional[str] = Field(None, max_length=300)
    signing_secret: Optional[str] = Field(None, max_length=300)
    slack_channel: Optional[str] = Field(None, max_length=50)


class ChatChannelUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    events: Optional[List[str]] = Field(None, min_length=1, max_length=20)
    min_alert_severity: Optional[Literal["info", "low", "medium", "high", "critical"]] = None
    enabled: Optional[bool] = None


class ChatMessage(BaseModel):
    id: str
    event: str
    status: str
    attempts: int = 0
    error: Optional[str] = None
    created_at: datetime
    sent_at: Optional[datetime] = None


def _refused(error: Exception) -> HTTPException:
    if isinstance(error, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error).strip("'"))
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


@router.get("/events", response_model=List[ChatEvent])
async def events(current_user: User = Depends(get_current_active_user)):
    """What a channel can be told about."""
    return [{"name": name, "description": description} for name, description in chat.EVENTS.items()]


@router.get("/channels", response_model=List[ChatChannel])
async def list_channels(admin: User = Depends(require_admin)):
    return await chat.list_channels()


@router.post("/channels", response_model=ChatChannel, status_code=status.HTTP_201_CREATED)
async def create_channel(body: NewChatChannel, admin: User = Depends(require_admin)):
    """Add a Slack or Teams channel (administrators only). A Slack app's token is checked with Slack first."""
    try:
        return await chat.create(body.model_dump(), {"id": admin.id, "name": admin.username})
    except chat.ChatError as e:
        raise _refused(e)


@router.patch("/channels/{channel_id}", response_model=ChatChannel)
async def update_channel(body: ChatChannelUpdate, channel_id: str = Path(...), admin: User = Depends(require_admin)):
    try:
        return await chat.update(channel_id, body.model_dump(exclude_unset=True))
    except (chat.ChatError, LookupError) as e:
        raise _refused(e)


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(channel_id: str = Path(...), admin: User = Depends(require_admin)) -> None:
    try:
        await chat.delete(channel_id)
    except LookupError as e:
        raise _refused(e)


@router.post("/channels/{channel_id}/test", status_code=status.HTTP_204_NO_CONTENT)
async def test_channel(channel_id: str = Path(...), admin: User = Depends(require_admin)) -> None:
    """Send a test message now; the answer says why if it does not get through."""
    try:
        await chat.send_test(channel_id)
    except (chat.ChatError, LookupError) as e:
        raise _refused(e)


@router.get("/channels/{channel_id}/messages", response_model=List[ChatMessage])
async def channel_messages(channel_id: str = Path(...), admin: User = Depends(require_admin)):
    """What was sent to the channel lately, and how it went."""
    return await chat.messages_of(channel_id)


# Slack calls this itself: no UTDRS session; Slack's signature with the channel's signing secret instead.
slack_router = APIRouter()


@slack_router.post("/slack/{channel_id}/interactions", include_in_schema=False)
async def slack_interactions(request: Request, channel_id: str,
                             x_slack_request_timestamp: str = Header(""), x_slack_signature: str = Header("")) -> Response:
    body = await request.body()
    if not await chat.slack_interaction(channel_id, x_slack_request_timestamp, x_slack_signature, body):
        await audit.record("chat.slack_request_refused", request, actor={"type": "anonymous", "name": "slack"}, outcome="denied",
                           target={"type": "chat_channel", "id": channel_id}, tenant_id="platform")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a genuine request from Slack for this channel")
    return Response(status_code=status.HTTP_200_OK)

