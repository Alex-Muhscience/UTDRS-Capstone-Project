import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, colleague, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-11-05T06:00:00+00:00"
const catalogue = {
  areas: [
    { area: "alerts", label: "Alerts", read: "See alerts", write: "Triage alerts" },
    { area: "cases", label: "Cases", read: "See cases", write: "Work cases" },
    { area: "rules", label: "Detection rules", read: "See detection rules", write: null },
  ],
  built_in: [
    { role: "admin", name: "Administrator", description: "Runs the organisation", permissions: [] },
    { role: "analyst", name: "Analyst", description: "Investigates", permissions: [] },
    { role: "viewer", name: "Read-only", description: "Looks", permissions: [] },
  ],
}
const triage = { id: "665f1c2ab1e2c3d4e5f60r01", name: "Triage", description: "First line", permissions: ["alerts:read", "alerts:write"], people: 0,
                 created_at: now, updated_at: now }

describe("custom roles", () => {
  it("are made from permissions, area by area", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/roles/permissions": catalogue,
      "GET /api/v1/roles": [],
      "POST /api/v1/roles": triage,
    })
    const { user: person } = renderApp("/roles")
    await person.click(await screen.findByRole("button", { name: "New role" }))
    const dialog = screen.getByRole("dialog")
    await person.type(within(dialog).getByLabelText(/^Name/), "Triage")
    await person.click(within(within(dialog).getByRole("radiogroup", { name: "Alerts" })).getByLabelText("See and change"))
    await person.click(within(within(dialog).getByRole("radiogroup", { name: "Cases" })).getByLabelText("See"))
    // Changing rules is for administrators: no such choice.
    expect(within(within(dialog).getByRole("radiogroup", { name: "Detection rules" })).queryByLabelText("See and change")).not.toBeInTheDocument()
    await person.click(within(dialog).getByRole("button", { name: "Create" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toEqual({
      name: "Triage", description: "", permissions: ["alerts:write", "cases:read"],
    })
  })

  it("are given to people on the Users page, and read-only is really read-only", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/roles": [triage],
      [`PATCH /api/v1/users/${colleague.id}`]: { ...colleague, role: "custom", custom_role_id: triage.id },
      "POST /api/v1/users/": { user: { ...colleague, role: "viewer" }, temporary_password: "temp-1234" },
    })
    const { user: person } = renderApp("/users")
    const select = await screen.findByRole("combobox", { name: new RegExp(`Role of ${colleague.firstName}`) })
    await waitFor(() => expect(within(select).getByRole("option", { name: "Triage" })).toBeInTheDocument())
    await person.selectOptions(select, "Triage")
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ role: "custom", custom_role_id: triage.id })

    await person.click(screen.getByRole("button", { name: "Add user" }))
    const dialog = screen.getByRole("dialog")
    await person.type(within(dialog).getByLabelText(/^Username/), "rae")
    await person.type(within(dialog).getByLabelText(/^Email/), "rae@example.com")
    await person.selectOptions(within(dialog).getByLabelText(/^Role/), "Read-only")
    await person.click(within(dialog).getByRole("button", { name: "Add user" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toMatchObject({ role: "viewer" })
  })

  it("show people only the parts of the dashboard their role includes", async () => {
    const me = { ...user, role: "custom" as const, custom_role_id: triage.id, custom_role_name: "Triage", permissions: ["alerts:read", "alerts:write"] }
    mockGateway({ ...shellRoutes(me) })
    renderApp("/events")
    expect(await screen.findByText("Not part of your role")).toBeInTheDocument()
    const nav = screen.getByRole("navigation", { name: "Main" })
    expect(within(nav).getByRole("link", { name: /Alerts/ })).toBeInTheDocument()
    expect(within(nav).queryByRole("link", { name: "Events" })).not.toBeInTheDocument()
    expect(screen.getAllByText("Triage").length).toBeGreaterThan(0) // their role, by name
  })
})
