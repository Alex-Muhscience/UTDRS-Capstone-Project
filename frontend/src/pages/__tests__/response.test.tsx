import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import type { Action, ActionType, Playbook } from "@/api/client"
import { admin, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-09T10:00:00+00:00"
const caseId = "665f1c2ab1e2c3d4e5f60501"

function anAction(overrides: Partial<Action> = {}): Action {
  return {
    id: "665f1c2ab1e2c3d4e5f60701",
    action: "m365.revoke_sessions",
    label: "Sign out everywhere",
    target: { type: "user", value: "jsmith@contoso.example" },
    params: {},
    status: "pending",
    mode: "approval",
    reason: "Your organisation's response mode is approval",
    protected: false,
    case_id: caseId,
    alert_id: null,
    playbook: { id: "p1", name: "Account takeover" },
    requested_by: { type: "playbook", id: "p1", name: "Account takeover" },
    decided_by: null,
    created_at: now,
    started_at: null,
    finished_at: null,
    result: null,
    error: null,
    can_undo: false,
    undoes: null,
    undone_by: null,
    ...overrides,
  }
}

const types: ActionType[] = [
  { name: "m365.revoke_sessions", label: "Sign out everywhere", description: "", connector: "m365", connector_name: "Microsoft 365", target: "user", params: [], can_undo: false, disruptive: true, connected: false },
  { name: "utdrs.escalate_case", label: "Raise the case's priority", description: "", connector: "utdrs", connector_name: "UTDRS", target: "case", params: ["priority"], can_undo: true, disruptive: false, connected: true },
]

function aPlaybook(overrides: Partial<Playbook> = {}): Playbook {
  return {
    id: "665f1c2ab1e2c3d4e5f60801",
    name: "Account takeover",
    description: "Sign them out everywhere.",
    enabled: true,
    mode: "approval",
    trigger: { min_severity: "high", tags: ["brute-force"], techniques: ["T1110"] },
    steps: [{ action: "m365.revoke_sessions", target: "user", params: {} }],
    built_in: "account-takeover",
    created_at: now,
    updated_at: now,
    last_run_at: null,
    ...overrides,
  }
}

describe("response", () => {
  it("shows what waits for a decision, and approves it", async () => {
    const pending = anAction()
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/response/actions": [pending],
      "GET /api/v1/response/settings": { mode: "approval", max_actions_per_hour: 20, protected_accounts: [] },
      [`POST /api/v1/response/actions/${pending.id}/approve`]: { ...pending, status: "succeeded", result: { summary: "Signed out" } },
    })
    const { user: person } = renderApp("/response")
    const waiting = (await screen.findByRole("heading", { name: "Waiting for a decision" })).closest("section") as HTMLElement
    expect(await within(waiting).findByText("jsmith@contoso.example")).toBeInTheDocument()
    expect(within(waiting).getByText("Your organisation's response mode is approval")).toBeInTheDocument()
    expect(within(waiting).getByText(/Playbook "Account takeover"/)).toBeInTheDocument()
    // People who are not administrators see the limits but cannot change them.
    expect(screen.getByText("Set by your administrators.")).toBeInTheDocument()

    await person.click(within(waiting).getByRole("button", { name: "Approve" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/approve"))).toBe(true))
  })

  it("lets an administrator change the safety limits", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/response/settings": { mode: "approval", max_actions_per_hour: 20, protected_accounts: [] },
      "PATCH /api/v1/response/settings": { mode: "automatic", max_actions_per_hour: 5, protected_accounts: ["ceo@contoso.example"] },
    })
    const { user: person } = renderApp("/response")
    await person.selectOptions(await screen.findByLabelText("Playbooks may"), "automatic")
    await person.clear(screen.getByLabelText("Most actions on their own in an hour"))
    await person.type(screen.getByLabelText("Most actions on their own in an hour"), "5")
    await person.type(screen.getByLabelText("Protected accounts"), "ceo@contoso.example")
    await person.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({
      mode: "automatic",
      max_actions_per_hour: 5,
      protected_accounts: ["ceo@contoso.example"],
    })
  })

  it("describes playbooks, says what is not connected, and turns one off", async () => {
    const playbook = aPlaybook()
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/playbooks/": [playbook],
      "GET /api/v1/response/actions/types": types,
      [`PATCH /api/v1/playbooks/${playbook.id}`]: { ...playbook, enabled: false },
    })
    const { user: person } = renderApp("/playbooks")
    expect(await screen.findByText(/High or worse alerts about Brute force, T1110/)).toBeInTheDocument()
    expect(await screen.findByText(/needs Microsoft 365, which is not connected/)).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "Turn off" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ enabled: false })
  })

  it("shows a case's actions and runs a playbook against it", async () => {
    const done = anAction({ action: "utdrs.escalate_case", label: "Raise the case's priority", target: { type: "case", value: caseId }, status: "succeeded", can_undo: true, result: { summary: "Priority raised from high to critical" } })
    const playbook = aPlaybook({ id: "665f1c2ab1e2c3d4e5f60802", name: "Ransomware" })
    const { calls } = mockGateway({
      ...shellRoutes(user),
      [`GET /api/v1/cases/${caseId}`]: {
        id: caseId, title: "Shadow copies deleted", status: "open", priority: "critical", owner_id: null, alert_ids: [], entities: [], techniques: [],
        first_seen: now, last_seen: now, created_at: now, updated_at: now, due_at: now, breached: false, timeline: [], explanation: null,
      },
      [`GET /api/v1/cases/${caseId}/evidence`]: { alerts: [], events: [], entities: [] },
      "GET /api/v1/response/actions": [done],
      "GET /api/v1/playbooks/": [playbook],
      [`POST /api/v1/playbooks/${playbook.id}/run`]: { actions: [], skipped: ["Sign out everywhere: Microsoft 365 is not connected"] },
    })
    const { user: person } = renderApp(`/cases/${caseId}`)
    expect(await screen.findByText("Priority raised from high to critical")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Undo" })).toBeInTheDocument()
    expect(calls.some((call) => call.path === "/api/v1/response/actions" && call.url.searchParams.get("case_id") === caseId)).toBe(true)

    await person.selectOptions(screen.getByLabelText("Playbook"), playbook.id)
    await person.click(screen.getByRole("button", { name: "Run" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/run"))).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/run"))?.body ?? "{}")).toEqual({ case_id: caseId })
  })
})
