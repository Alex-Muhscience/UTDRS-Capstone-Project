"""The MCP tools, called as an assistant would, against a stand-in for the UTDRS gateway."""
import json

import httpx
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import gateway
from server import mcp

KEY = "utdrs_abcd1234_secret"
CASE = {"id": "c1", "title": "Shadow copies deleted — fin-ws-07", "status": "open", "priority": "critical", "owner_id": None, "breached": False,
        "due_at": "2026-10-18T07:00:00Z", "first_seen": "x", "last_seen": "x", "entities": [{"type": "host", "value": "fin-ws-07"}],
        "techniques": ["T1490"], "alert_ids": ["a1"], "created_at": "x", "updated_at": "x",
        "explanation": {"what_happened": "1 alert", "why_it_matters": "ransomware", "next_steps": ["Disconnect it"]},
        "timeline": [{"at": "x", "kind": "created", "text": "Opened", "actor": None, "data": {}}]}


class Gateway:
    def __init__(self):
        self.calls = []
        self.routes = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path.removeprefix("/api/v1"), dict(request.url.params), body, request.headers.get("authorization")))
        key = f"{request.method} {request.url.path.removeprefix('/api/v1')}"
        status, payload = self.routes.get(key, (404, {"detail": f"No route {key}"}))
        return httpx.Response(status, json=payload)


@pytest.fixture
def fake(monkeypatch):
    stand_in = Gateway()
    monkeypatch.setattr(gateway, "transport", httpx.MockTransport(stand_in.handler))
    monkeypatch.setenv("UTDRS_API_KEY", KEY)
    return stand_in


def result(called):
    assert not called.isError, called.content
    return called.structuredContent.get("result", called.structuredContent)


@pytest.mark.asyncio
async def test_tools_say_what_they_change():
    async with create_connected_server_and_client_session(mcp) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert {"list_cases", "get_case", "get_case_evidence", "list_alerts", "get_alert", "search_events", "list_pending_actions",
            "list_response_actions", "detector_quality", "update_case", "give_verdict", "propose_action", "check_email"} == set(tools)
    assert tools["get_case"].annotations.readOnlyHint is True
    assert tools["propose_action"].annotations.destructiveHint is True and tools["update_case"].annotations.readOnlyHint is False
    assert "confirm" in tools["propose_action"].inputSchema["required"]


@pytest.mark.asyncio
async def test_reading_cases_as_the_caller(fake):
    fake.routes["GET /cases/"] = (200, [CASE])
    fake.routes["GET /cases/c1"] = (200, CASE)
    async with create_connected_server_and_client_session(mcp) as client:
        cases = result(await client.call_tool("list_cases", {}))
        case = result(await client.call_tool("get_case", {"case_id": "c1"}))
    assert cases[0]["title"].startswith("Shadow copies") and "timeline" not in cases[0]
    assert case["explanation"]["next_steps"] == ["Disconnect it"] and case["timeline"] == [{"at": "x", "kind": "created", "text": "Opened"}]
    method, path, params, _, auth = fake.calls[0]
    assert (method, path, params, auth) == ("GET", "/cases/", {"limit": "20", "open_only": "true"}, f"Bearer {KEY}")


@pytest.mark.asyncio
async def test_proposing_needs_confirmation_and_only_proposes(fake):
    fake.routes["POST /response/actions"] = (201, {"id": "x1", "label": "Sign out everywhere", "status": "pending", "reason": "Requested through an API key",
                                                    "target": {"type": "user", "value": "jsmith@contoso.example"}, "case_id": "c1", "params": {}})
    async with create_connected_server_and_client_session(mcp) as client:
        refused = await client.call_tool("propose_action", {"action": "m365.revoke_sessions", "target_type": "user", "target_value": "jsmith@contoso.example", "confirm": False})
        assert refused.isError and "confirm" in refused.content[0].text and fake.calls == []
        done = result(await client.call_tool("propose_action", {"action": "m365.revoke_sessions", "target_type": "user",
                                                                 "target_value": "jsmith@contoso.example", "confirm": True, "case_id": "c1"}))
    assert done["status"] == "pending" and done["reason"] == "Requested through an API key"
    assert fake.calls[0][3] == {"action": "m365.revoke_sessions", "target": {"type": "user", "value": "jsmith@contoso.example"}, "params": {}, "case_id": "c1"}


@pytest.mark.asyncio
async def test_refusals_are_explained(fake):
    fake.routes["GET /alerts/"] = (403, {"detail": "This API key does not have the alerts:read scope"})
    async with create_connected_server_and_client_session(mcp) as client:
        denied = await client.call_tool("list_alerts", {})
        missing = await client.call_tool("get_case", {"case_id": "nope"})
    assert denied.isError and "alerts:read scope" in denied.content[0].text and "give the API key" in denied.content[0].text
    assert missing.isError and "Not found: " in missing.content[0].text


@pytest.mark.asyncio
async def test_updating_a_case_and_giving_a_verdict(fake):
    fake.routes["PATCH /cases/c1"] = (200, {**CASE, "status": "investigating"})
    fake.routes["POST /cases/c1/notes"] = (201, {**CASE, "status": "investigating"})
    fake.routes["POST /alerts/a1/feedback"] = (200, {"alert": {"id": "a1", "title": "x", "status": "false_positive", "feedback": {"verdict": "false_positive"}},
                                                     "suggestion": {"name": "x", "detector": "signature:x", "entity": None, "max_severity": "medium"}})
    async with create_connected_server_and_client_session(mcp) as client:
        case = result(await client.call_tool("update_case", {"case_id": "c1", "status": "investigating", "note": "Checked the VPN logs."}))
        verdict = result(await client.call_tool("give_verdict", {"alert_id": "a1", "verdict": "false_positive"}))
        empty = await client.call_tool("update_case", {"case_id": "c1"})
    assert case["status"] == "investigating" and [c[1] for c in fake.calls[:2]] == ["/cases/c1", "/cases/c1/notes"]
    assert verdict["alert"]["status"] == "false_positive" and verdict["suggested_suppression"]["detector"] == "signature:x"
    assert empty.isError


@pytest.mark.asyncio
async def test_large_events_are_trimmed(fake):
    fake.routes["GET /events/search/"] = (200, [{"id": "e1", "event_type": "process", "description": "x", "raw_data": {f"k{i}": "v" * 100 for i in range(50)}}])
    async with create_connected_server_and_client_session(mcp) as client:
        [event] = result(await client.call_tool("search_events", {"query": "fin-ws-07"}))
    assert event["truncated"] is True and len(event["raw_data"]) == 20


@pytest.mark.asyncio
async def test_resources_and_prompts(fake):
    fake.routes["GET /cases/c1"] = (200, CASE)
    async with create_connected_server_and_client_session(mcp) as client:
        templates = {t.uriTemplate for t in (await client.list_resource_templates()).resourceTemplates}
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        read = await client.read_resource("utdrs://cases/c1")
    assert templates == {"utdrs://cases/{case_id}", "utdrs://alerts/{alert_id}"}
    assert prompts == {"triage_open_cases", "investigate_case", "explain_to_customer"}
    assert json.loads(read.contents[0].text)["title"].startswith("Shadow copies")


@pytest.mark.asyncio
async def test_no_key_no_calls(monkeypatch):
    monkeypatch.delenv("UTDRS_API_KEY", raising=False)
    async with create_connected_server_and_client_session(mcp) as client:
        called = await client.call_tool("list_cases", {})
    assert called.isError and "UTDRS_API_KEY" in called.content[0].text
