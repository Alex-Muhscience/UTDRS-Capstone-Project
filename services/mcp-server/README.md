# UTDRS MCP server

Lets AI assistants (Claude, other [MCP](https://modelcontextprotocol.io) clients, an organisation's own agents) investigate and act through UTDRS, with exactly the permissions of the API key they are given, and every change in UTDRS's audit log under that key's name.

It is a thin layer over the gateway's public API: no database, no credentials of its own. Tenancy, scopes, rate limits and auditing apply as they do to anyone else.

## Tools

| Tool | Does | Changes anything | API key scope |
|---|---|---|---|
| `list_cases`, `get_case`, `get_case_evidence` | Cases, their plain-language explanation, timeline, alerts and events | No | `cases:read` |
| `list_alerts`, `get_alert` | Alerts, and what the engine found | No | `alerts:read` |
| `search_events` | Events mentioning a user, address, host or process | No | `events:read` |
| `list_response_actions`, `list_pending_actions` | What UTDRS can do, and what waits for a decision | No | `response:read` |
| `detector_quality` | Noisy detectors and precision | No | `tuning:read` |
| `update_case` | Status, priority, a note | Yes | `cases:write` |
| `give_verdict` | Real threat, false positive or expected activity | Yes | `alerts:write` |
| `check_email` | Check a delivered email for phishing | Yes (stores the result) | `email:write`, `events:read`, `alerts:read` |
| `propose_action` | Propose a response action, with `confirm: true` | Proposes only: a person approves it in UTDRS | `response:write` |

Read tools are marked read-only and the rest are marked as changing things (MCP tool annotations). An assistant can never run a response action by itself: actions asked for through an API key always wait for a person's approval in UTDRS, and the tool refuses without an explicit `confirm`. Answers are trimmed (lists capped, large event details cut) so they fit an assistant's context.

**Resources:** `utdrs://cases/{id}`, `utdrs://alerts/{id}`. **Prompts:** `triage_open_cases`, `investigate_case`, `explain_to_customer`.

## Connecting an assistant

Create an API key in the dashboard (API keys) with the scopes the assistant should have, for example `cases:read`, `cases:write`, `alerts:read`, `alerts:write`, `events:read`, `response:read` and `response:write`.

**Over HTTP** (the Docker Compose stack runs it at `http://localhost:8765/mcp`). Claude Code:

```bash
claude mcp add --transport http utdrs http://localhost:8765/mcp --header "Authorization: Bearer utdrs_..."
```

Other clients: the Streamable HTTP endpoint `/mcp`, with `Authorization: Bearer <API key>` on every request. Requests without a UTDRS API key get 401 before any session starts. Host headers are checked against `MCP_ALLOWED_HOSTS` (DNS-rebinding protection); add your public name when exposing it, behind HTTPS.

**Over stdio**, for an assistant on the same machine (Claude Desktop's `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "utdrs": {
      "command": "python",
      "args": ["/path/to/services/mcp-server/server.py"],
      "env": {"UTDRS_GATEWAY_URL": "http://localhost:8000", "UTDRS_API_KEY": "utdrs_..."}
    }
  }
}
```

## Configuration

| Setting | Default | |
|---|---|---|
| `UTDRS_GATEWAY_URL` | `http://localhost:8000` | The gateway |
| `UTDRS_API_KEY` | | Over stdio only: the key to act with |
| `MCP_HOST`, `MCP_PORT` | `127.0.0.1`, `8765` | Where the HTTP server listens |
| `MCP_ALLOWED_HOSTS` | `localhost:*,127.0.0.1:*` | Host headers accepted |

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

11 tests: every tool called as an assistant would through the SDK's in-memory client, against a stand-in gateway (the caller's key forwarded, refusals explained, `confirm` required, answers trimmed, resources and prompts); and over HTTP, requests without an API key refused, a tool call carrying the caller's key, and unknown hosts refused.

## Not yet

OAuth 2.1 as the MCP authorisation specification describes (so assistants sign in rather than use a pasted key); `get_posture`, `lookup_indicator` and coverage tools, which wait for those features in UTDRS.
