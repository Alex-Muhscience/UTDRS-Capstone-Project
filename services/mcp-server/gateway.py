"""
The UTDRS API, as the MCP server uses it: every tool is one or two calls to the public
API with the caller's own credential, so tenancy, scopes, rate limits and the audit log
apply exactly as they do to anyone else. The server keeps no data and holds no
credentials of its own.
"""
import os
from typing import Any, Dict, Optional

import httpx
from mcp.server.fastmcp.exceptions import ToolError

TIMEOUT = httpx.Timeout(30.0, connect=5.0)

# For tests: a transport standing in for the gateway.
transport: Optional[httpx.AsyncBaseTransport] = None


def base_url() -> str:
    return os.environ.get("UTDRS_GATEWAY_URL", "http://localhost:8000").rstrip("/") + "/api/v1"


async def call(token: str, method: str, path: str, **kwargs) -> Any:
    """One API call as the caller. Turns the gateway's refusals into errors the assistant can read."""
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "UTDRS-MCP/1", "X-UTDRS-Client": "mcp"}
    try:
        async with httpx.AsyncClient(base_url=base_url(), timeout=TIMEOUT, transport=transport) as client:
            response = await client.request(method, path, headers=headers, **kwargs)
    except httpx.HTTPError as e:
        raise ToolError(f"Could not reach UTDRS: {e.__class__.__name__}")
    if response.status_code == 401:
        raise ToolError("UTDRS refused the credential: use a valid, unrevoked API key")
    if response.status_code == 403:
        raise ToolError(f"Not allowed: {_detail(response)} (give the API key the scope this needs)")
    if response.status_code == 404:
        raise ToolError(f"Not found: {_detail(response)}")
    if response.is_error:
        raise ToolError(f"UTDRS answered {response.status_code}: {_detail(response)}")
    return response.json() if response.content else None


def _detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return response.text[:300]
    if isinstance(detail, list) and detail:
        return "; ".join(str(d.get("msg", d)) for d in detail[:3])
    return str(detail or response.reason_phrase)


def pick(item: Dict[str, Any], *fields: str) -> Dict[str, Any]:
    """Only the fields an assistant needs, so answers stay small."""
    return {f: item.get(f) for f in fields if f in item}
