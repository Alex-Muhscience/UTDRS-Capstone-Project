import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { DetectionRule } from "@/api/client"
import { admin, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-11-05T10:00:00+00:00"
const ID = "665f1c2ab1e2c3d4e5f60701"
const encoded = { name: "Encoded PowerShell", event: { event_type: "process", process_name: "powershell.exe", command_line: "-enc x" }, expect: "match" as const }

function aRule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    id: ID, name: "Encoded PowerShell", description: "x", rule_type: "signature", detection_source: "endpoint", severity: "high",
    status: "enabled", tags: [], logic: "process_name == 'powershell.exe' and command_line matches '(?i)-enc'",
    test_cases: [encoded], created_at: now, updated_at: now, performance_metrics: {}, metadata: {}, version: 2,
    engine: { runs: true, reason: null }, ...overrides,
  }
}

const versions = [
  { version: 2, change: "updated", changed_by: admin.id, at: now, rule: { severity: "high" } },
  { version: 1, change: "created", changed_by: admin.id, at: now, rule: { severity: "medium" } },
]

describe("rule test cases and history", () => {
  it("runs a rule's tests and shows which pass", async () => {
    mockGateway({
      ...shellRoutes(user),
      [`GET /api/v1/detection/rules/${ID}`]: aRule(),
      [`GET /api/v1/detection/rules/${ID}/versions`]: versions,
      [`POST /api/v1/detection/rules/${ID}/test`]: { ran: true, reason: null, passed: true, results: [{ name: encoded.name, expect: "match", matched: true, passed: true }] },
    })
    const { user: person } = renderApp(`/rules/${ID}`)
    const card = (await screen.findByRole("heading", { name: "Test cases" })).closest("section") as HTMLElement
    expect(within(card).getByText("Must match")).toBeInTheDocument()
    await person.click(within(card).getByRole("button", { name: /Run tests/ }))
    expect(await within(card).findByText("All 1 pass")).toBeInTheDocument()
    expect(within(card).getByLabelText("Passes")).toBeInTheDocument()
    // Analysts run tests but do not change them.
    expect(within(card).queryByRole("button", { name: /Add a test case/ })).not.toBeInTheDocument()
  })

  it("lets administrators add a test case, and says why a change is refused", async () => {
    let refuse = true
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      [`GET /api/v1/detection/rules/${ID}`]: aRule(),
      [`GET /api/v1/detection/rules/${ID}/versions`]: versions,
      [`PUT /api/v1/detection/rules/${ID}`]: () =>
        refuse ? json({ detail: "Not saved: 1 of 2 test cases fail: 'cmd' expected a match but got none" }, 422) : aRule(),
    })
    const { user: person } = renderApp(`/rules/${ID}`)
    const card = (await screen.findByRole("heading", { name: "Test cases" })).closest("section") as HTMLElement
    await person.click(within(card).getByRole("button", { name: /Add a test case/ }))
    await person.type(within(card).getByLabelText(/^Name/), "cmd")
    await person.click(within(card).getByLabelText(/^Event/))
    await person.paste('{"event_type": "process", "process_name": "cmd.exe"}')
    await person.click(within(card).getByRole("button", { name: "Add" }))
    expect(await within(card).findByText(/test cases fail/)).toBeInTheDocument()
    const sent = JSON.parse(calls.filter((call) => call.method === "PUT").at(-1)?.body ?? "{}")
    expect(sent.test_cases).toEqual([encoded, { name: "cmd", event: { event_type: "process", process_name: "cmd.exe" }, expect: "match" }])
    refuse = false
  })

  it("shows the history and restores an earlier version", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      [`GET /api/v1/detection/rules/${ID}`]: aRule(),
      [`GET /api/v1/detection/rules/${ID}/versions`]: versions,
      [`POST /api/v1/detection/rules/${ID}/versions/1/restore`]: aRule({ severity: "medium", version: 3 }),
    })
    const { user: person } = renderApp(`/rules/${ID}`)
    const history = within(await screen.findByRole("list", { name: "Versions" }))
    expect(history.getByText(/Version 2/)).toBeInTheDocument()
    // Only earlier versions can be restored.
    expect(history.getAllByRole("button", { name: "Restore" })).toHaveLength(1)
    await person.click(history.getByRole("button", { name: "Restore" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/versions/1/restore"))).toBe(true))
  })
})
