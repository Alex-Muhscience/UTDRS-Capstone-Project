import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import type { Case } from "@/api/client"
import { admin, alert, colleague, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-09T10:00:00+00:00"

function aCase(overrides: Partial<Case> = {}): Case {
  return {
    id: "665f1c2ab1e2c3d4e5f60501",
    title: "Shadow copies deleted — fin-ws-07",
    status: "open",
    priority: "critical",
    owner_id: null,
    alert_ids: [alert().id],
    entities: [{ type: "host", value: "fin-ws-07" }],
    techniques: ["T1490"],
    first_seen: now,
    last_seen: now,
    created_at: now,
    updated_at: now,
    due_at: "2026-10-09T11:00:00+00:00",
    breached: true,
    attachments: [],
    timeline: [
      { at: now, kind: "created", actor: null, text: "Opened for this alert", data: {} },
      { at: now, kind: "alert_added", actor: null, text: "Shadow copies deleted", data: {} },
    ],
    explanation: {
      what_happened: "1 alert (Shadow copies deleted) involving fin-ws-07, at 09 Oct 10:00 UTC.",
      why_it_matters: "It looks like deleting backups so files cannot be recovered (a ransomware step). Treat it as urgent: act within the hour.",
      next_steps: ["Disconnect the affected computer from the network now", "Check that backups are intact and offline"],
    },
    ...overrides,
  }
}

const evidence = { alerts: [{ ...alert(), id: alert().id }], events: [], entities: [{ type: "host", value: "fin-ws-07" }] }

describe("cases", () => {
  it("lists active cases, with overdue ones flagged", async () => {
    const { calls } = mockGateway({ ...shellRoutes(user), "GET /api/v1/cases/": [aCase()] })
    renderApp("/cases")
    const table = await screen.findByRole("table", { name: "Cases" })
    expect(within(table).getByText("Shadow copies deleted — fin-ws-07")).toBeInTheDocument()
    expect(within(table).getByText("Overdue")).toBeInTheDocument()
    expect(within(table).getByText("Unassigned")).toBeInTheDocument()
    expect(calls.find((call) => call.path === "/api/v1/cases/")?.url.searchParams.get("open_only")).toBe("true")
  })

  it("explains a case and shows its timeline", async () => {
    const item = aCase()
    mockGateway({ ...shellRoutes(user), [`GET /api/v1/cases/${item.id}`]: item, [`GET /api/v1/cases/${item.id}/evidence`]: evidence })
    renderApp(`/cases/${item.id}`)
    expect(await screen.findByText(/deleting backups so files cannot be recovered/)).toBeInTheDocument()
    expect(screen.getByText("Disconnect the affected computer from the network now")).toBeInTheDocument()
    expect(screen.getByText("Case opened")).toBeInTheDocument()
    expect(await screen.findByRole("link", { name: alert().title })).toHaveAttribute("href", `/alerts/${alert().id}`)
  })

  it("moves a case on, assigns it, and adds notes", async () => {
    const item = aCase()
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      [`GET /api/v1/cases/${item.id}`]: item,
      [`GET /api/v1/cases/${item.id}/evidence`]: evidence,
      [`PATCH /api/v1/cases/${item.id}`]: { ...item, status: "investigating" },
      [`POST /api/v1/cases/${item.id}/notes`]: item,
    })
    const { user: person } = renderApp(`/cases/${item.id}`)
    await person.click(await screen.findByRole("button", { name: "Start investigating" }))
    await waitFor(() => expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(1))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ status: "investigating" })

    await person.selectOptions(screen.getByLabelText("Owner"), colleague.id)
    await waitFor(() => expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(2))
    expect(JSON.parse(calls.filter((call) => call.method === "PATCH")[1]?.body ?? "{}")).toEqual({ owner_id: colleague.id })

    await person.type(screen.getByLabelText("Note"), "Isolated the laptop.")
    await person.click(screen.getByRole("button", { name: "Add note" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toEqual({ text: "Isolated the laptop." })
  })

  it("links an alert to its case", async () => {
    const withCase = alert({ case_id: "665f1c2ab1e2c3d4e5f60501" })
    mockGateway({ ...shellRoutes(user), [`GET /api/v1/alerts/${withCase.id}`]: withCase, "GET /api/v1/events/": [] })
    renderApp(`/alerts/${withCase.id}`)
    expect(await screen.findByRole("link", { name: "Part of a case" })).toHaveAttribute("href", "/cases/665f1c2ab1e2c3d4e5f60501")
  })
})

describe("case files", () => {
  const file = {
    id: "665f1c2ab1e2c3d4e5f60901", name: "invoice.eml", content_type: "message/rfc822", size: 2048, sha256: "a".repeat(64),
    uploaded_by: { type: "user", id: user.id, name: "ann" }, uploaded_at: now,
  }

  it("attaches, downloads and removes files", async () => {
    URL.createObjectURL = vi.fn(() => "blob:file")
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
    let attachments: (typeof file)[] = []
    const { calls } = mockGateway({
      ...shellRoutes(user),
      [`GET /api/v1/cases/${aCase().id}`]: () => aCase({ attachments }),
      [`GET /api/v1/cases/${aCase().id}/evidence`]: evidence,
      "GET /api/v1/response/actions": [],
      [`POST /api/v1/cases/${aCase().id}/attachments`]: () => {
        attachments = [file]
        return new Response(JSON.stringify(file), { status: 201, headers: { "Content-Type": "application/json" } })
      },
      [`GET /api/v1/cases/${aCase().id}/attachments/${file.id}`]: () => new Response(new Blob(["From: x"]), { headers: { "Content-Type": "application/octet-stream" } }),
      [`DELETE /api/v1/cases/${aCase().id}/attachments/${file.id}`]: () => {
        attachments = []
        return new Response(null, { status: 204 })
      },
    })
    const { user: person } = renderApp(`/cases/${aCase().id}`)
    const card = (await screen.findByRole("heading", { name: "Files" })).closest("section") as HTMLElement
    await person.upload(within(card).getByLabelText("File to attach"), new File(["From: x"], "invoice.eml", { type: "message/rfc822" }))
    expect(await within(card).findByText("invoice.eml")).toBeInTheDocument()
    const upload = calls.find((call) => call.method === "POST" && call.path.endsWith("/attachments"))
    // jsdom's File reaches Node's FormData without its name or bytes; the gateway's tests cover real uploads.
    expect(upload?.body).toContain('name="file"')

    await person.click(within(card).getByRole("button", { name: "Download invoice.eml" }))
    await waitFor(() => expect(URL.createObjectURL).toHaveBeenCalled())

    await person.click(within(card).getByRole("button", { name: "Remove invoice.eml" }))
    await waitFor(() => expect(within(card).queryByText("invoice.eml")).not.toBeInTheDocument())
  })

  it("only lets whoever attached a file, or an administrator, remove it", async () => {
    mockGateway({
      ...shellRoutes(user),
      [`GET /api/v1/cases/${aCase().id}`]: aCase({ attachments: [{ ...file, uploaded_by: { type: "user", id: "someone-else", name: "bo" } }] }),
      [`GET /api/v1/cases/${aCase().id}/evidence`]: evidence,
      "GET /api/v1/response/actions": [],
    })
    renderApp(`/cases/${aCase().id}`)
    const card = (await screen.findByRole("heading", { name: "Files" })).closest("section") as HTMLElement
    expect(await within(card).findByRole("button", { name: "Download invoice.eml" })).toBeInTheDocument()
    expect(within(card).queryByRole("button", { name: "Remove invoice.eml" })).not.toBeInTheDocument()
  })
})
