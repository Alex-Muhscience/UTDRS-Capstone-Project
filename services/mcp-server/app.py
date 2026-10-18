"""
The MCP server over Streamable HTTP: `uvicorn app:app` (or `python app.py`), the MCP
endpoint at /mcp.

Every request must carry a bearer token: a UTDRS API key, which the server forwards to
the gateway on each call, so the client can do exactly what the key's scopes allow.
Requests without one are refused here, before any MCP session starts. Host headers are
checked against MCP_ALLOWED_HOSTS (DNS-rebinding protection).
"""
import os

from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse

from server import mcp

API_KEY_PREFIX = "utdrs_"


def _settings() -> None:
    hosts = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "localhost:*,127.0.0.1:*").split(",") if h.strip()]
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[])
    mcp.settings.stateless_http = True  # each request stands alone: nothing to keep between them


class RequireApiKey:
    """Refuse requests without a UTDRS API key as their bearer token."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") != "/health":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode("latin-1")
            if not (auth.lower().startswith("bearer ") and auth[7:].strip().startswith(API_KEY_PREFIX)):
                response = JSONResponse({"error": "Send a UTDRS API key as the bearer token"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


_settings()
_inner = mcp.streamable_http_app()


async def _health(scope, receive, send):
    await JSONResponse({"status": "ok"})(scope, receive, send)


class _App:
    """/health for the container's health check; everything else is MCP, behind the API-key check."""

    def __init__(self):
        self.mcp = RequireApiKey(_inner)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/health":
            await _health(scope, receive, send)
            return
        await self.mcp(scope, receive, send)


app = _App()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8765")))
