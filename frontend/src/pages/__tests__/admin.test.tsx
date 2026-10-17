import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { ApiKey, AuditEntry } from "@/api/client"
import { admin, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-09T10:00:00+00:00"
const SCOPES = ["alerts:read", "alerts:write", "events:read", "events:write", "assets:read", "assets:write"]

function apiKey(overrides: Partial<ApiKey> = {}): ApiKey {
  return {
    id: "665f1c2ab1e2c3d4e5f60401",
    name: "firewall-forwarder",
    prefix: "a1b2c3d4",
    scopes: ["events:write"],
    created_by: { id: admin.id, name: admin.username },
    created_at: now,
    expires_at: null,
    last_used_at: null,
    revoked_at: null,
    ...overrides,
  }
}

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    seq: 7,
    at: now,
    action: "rules.update_rule_status",
    outcome: "success",
    actor: { type: "user", id: admin.id, name: admin.username, role: "admin" },
    address: "198.51.100.4",
    request_id: "req-1",
    target: { type: "rule", id: "665f1c2ab1e2c3d4e5f60301" },
    changes: null,
    details: { query: { status: "disabled" } },
    prev_hash: "a".repeat(64),
    hash: "b".repeat(64),
    ...overrides,
  }
}

describe("API keys", () => {
  it("is for administrators only", async () => {
    mockGateway(shellRoutes(user))
    renderApp("/api-keys")
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument()
  })

  it("creates a key with the scopes chosen and shows it once", async () => {
    const created = apiKey({ id: "665f1c2ab1e2c3d4e5f60402", name: "siem-reader", scopes: ["alerts:read"] })
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/api-keys/": [apiKey()],
      "GET /api/v1/api-keys/scopes": SCOPES,
      "POST /api/v1/api-keys/": json({ api_key: created, key: "utdrs_a1b2c3d4_s3cr3t" }, 201),
    })
    const { user: person } = renderApp("/api-keys")

    const table = await screen.findByRole("table", { name: "API keys" })
    expect(within(table).getByText("firewall-forwarder")).toBeInTheDocument()
    expect(within(table).getByText("events:write")).toBeInTheDocument()

    await person.click(screen.getByRole("button", { name: /New key/ }))
    const dialog = screen.getByRole("dialog")
    await person.type(within(dialog).getByLabelText("Name *"), "siem-reader")
    const alertsRow = within(dialog).getByText("Alerts").closest("div")!
    await person.click(within(alertsRow).getByLabelText("read"))
    await person.click(within(dialog).getByRole("button", { name: "Create key" }))

    expect(await screen.findByLabelText("API key")).toHaveTextContent("utdrs_a1b2c3d4_s3cr3t")
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toEqual({
      name: "siem-reader",
      scopes: ["alerts:read"],
      expires_in_days: 90,
    })
  })

  it("revokes a key after asking", async () => {
    const key = apiKey()
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/api-keys/": [key, apiKey({ id: "665f1c2ab1e2c3d4e5f60403", name: "old-key", revoked_at: now })],
      "GET /api/v1/api-keys/scopes": SCOPES,
      [`DELETE /api/v1/api-keys/${key.id}`]: { ...key, revoked_at: now },
    })
    const { user: person } = renderApp("/api-keys")
    const table = await screen.findByRole("table", { name: "API keys" })
    // A revoked key has nothing left to do.
    const oldRow = within(table).getByText("old-key").closest("tr")!
    expect(within(oldRow).getByText("Revoked")).toBeInTheDocument()
    expect(within(oldRow).queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument()

    const row = within(table).getByText("firewall-forwarder").closest("tr")!
    await person.click(within(row).getByRole("button", { name: "Revoke" }))
    await person.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Revoke key" }))
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE")).toBe(true))
  })
})

describe("audit log", () => {
  it("lists who did what, and shows an entry's details", async () => {
    mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/audit-log/": [
        entry(),
        entry({
          seq: 6,
          action: "auth.login_failed",
          outcome: "denied",
          actor: { type: "anonymous", name: "mallory" },
          target: null,
          details: null,
        }),
        entry({ seq: 5, action: "assets.create_asset", actor: { type: "api_key", id: "k1", name: "cmdb-sync", scopes: ["assets:write"] }, target: { type: "asset", id: "a1", name: "srv-01" } }),
      ],
    })
    const { user: person } = renderApp("/audit-log")

    const table = await screen.findByRole("table", { name: "Audit log" })
    expect(within(table).getByText("Update rule status")).toBeInTheDocument()
    expect(within(table).getByText("mallory (not signed in)")).toBeInTheDocument()
    expect(within(table).getByText("Denied")).toBeInTheDocument()
    expect(within(table).getByText("API key cmdb-sync")).toBeInTheDocument()
    expect(within(table).getByText("Asset srv-01")).toBeInTheDocument()

    await person.click(within(table).getByRole("button", { name: "Update rule status" }))
    const dialog = screen.getByRole("dialog")
    expect(within(dialog).getByText("rules.update_rule_status")).toBeInTheDocument()
    expect(within(dialog).getByText(/disabled/)).toBeInTheDocument()
  })

  it("filters by kind of action, and verifies the chain", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/audit-log/": [entry()],
      "GET /api/v1/audit-log/verify": { ok: false, checked: 6, problem: "Entry 7 has been altered" },
    })
    const { user: person } = renderApp("/audit-log")
    await screen.findByRole("table", { name: "Audit log" })

    await person.selectOptions(screen.getByRole("combobox", { name: "Kind of action" }), "rules")
    await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("action") === "rules")).toBe(true))

    await person.click(screen.getByRole("button", { name: "Verify the log" }))
    expect(await screen.findByText("Entry 7 has been altered")).toBeInTheDocument()
  })
})
