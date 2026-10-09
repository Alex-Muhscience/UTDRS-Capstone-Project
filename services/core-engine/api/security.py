import hmac
from typing import Optional

from fastapi import Header, HTTPException, status

from config import settings


async def require_internal_token(x_internal_token: Optional[str] = Header(default=None)):
    """
    Reject callers that do not present the shared internal token, when one is configured.

    The core engine is an internal service behind the API gateway; the gateway sends
    INTERNAL_API_TOKEN in the X-Internal-Token header.
    """
    expected = settings.INTERNAL_API_TOKEN
    if not expected:
        return
    if not x_internal_token or not hmac.compare_digest(x_internal_token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token")
