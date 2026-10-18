"""The server over HTTP: API keys only, forwarded as they came."""
import json

import httpx
import pytest
from starlette.testclient import TestClient

import gateway

KEY = "utdrs_abcd1234_secret"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def client():
    """One client for the module: like uvicorn, the app's session manager starts once per process."""
    from app import app

    with TestClient(app) as test_client:
        yield test_client


def messages(response):
    """JSON-RPC messages from a Streamable HTTP response (JSON, or server-sent events)."""
    if response.headers["content-type"].startswith("application/json"):
        return [response.json()]
    return [json.loads(line[5:]) for line in response.text.splitlines() if line.startswith("data:")]


def test_requests_without_an_api_key_are_refused(client):
    assert client.post("/mcp", json=INIT, headers=HEADERS).status_code == 401
    assert client.post("/mcp", json=INIT, headers={**HEADERS, "Authorization": "Bearer not-a-utdrs-key"}).status_code == 401
    assert client.get("/health").json() == {"status": "ok"}


def test_a_tool_call_carries_the_callers_key(client, monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.headers["authorization"])
        return httpx.Response(200, json=[])

    monkeypatch.setattr(gateway, "transport", httpx.MockTransport(handler))
    auth = {**HEADERS, "Authorization": f"Bearer {KEY}"}
    started = client.post("/mcp", json=INIT, headers=auth)
    assert started.status_code == 200 and messages(started)[0]["result"]["serverInfo"]["name"] == "UTDRS"
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_alerts", "arguments": {}}}
    answered = client.post("/mcp", json=call, headers={**auth, "Mcp-Protocol-Version": "2025-06-18"})
    assert answered.status_code == 200 and not messages(answered)[0]["result"]["isError"]
    assert seen == [f"Bearer {KEY}"]


def test_unknown_hosts_are_refused(client):
    response = client.post("/mcp", json=INIT, headers={**HEADERS, "Authorization": f"Bearer {KEY}", "Host": "evil.example"})
    assert response.status_code in (400, 421)
