import { render, screen, waitFor, within } from "@testing-library/react"
import { Toaster } from "sonner"
import { afterEach, describe, expect, it } from "vitest"

import { admin, shellRoutes, tenant } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"
import { activeOrganisation, setActiveOrganisation } from "@/lib/organisation"

const now = "2026-11-05T06:00:00+00:00"
const globex = {
  id: "665f1c2ab1e2c3d4e5f60a02", name: "Globex", slug: "globex", status: "active", created_at: now, default: false, people: 2,
  administrators: 1, events_last_week: 340, open_alerts: 5, connectors: 1, last_sign_in: now, mfa_required: false, urgent_alerts: 2,
  msp: false, managed_by: tenant.id, managed_by_name: tenant.name,
}
const overview = { msp: true, organisation_id: tenant.id, organisation: tenant.name, role_in_clients: "admin", clients: [globex] }
const clientAlert = { id: "665f1c2ab1e2c3d4e5f60c09", title: "Mailbox rule forwards mail outside", severity: "critical", status: "open",
                      created_at: now, case_id: null, organisation_id: globex.id, organisation: "Globex" }

afterEach(() => setActiveOrganisation(null))

describe("service providers", () => {
  it("lists clients and works in one, sending its organisation with every request", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/msp": overview,
      "GET /api/v1/msp/alerts": [clientAlert],
      "GET /api/v1/alerts/": [],
      "GET /api/v1/tenants/current": (request) =>
        request.headers.get("X-UTDRS-Organisation") === globex.id ? { ...tenant, id: globex.id, name: "Globex", managed_by: tenant.id, managed_by_name: tenant.name } : tenant,
    })
    const { user: person } = renderApp("/clients")
    expect(await screen.findByRole("link", { name: "Clients" })).toBeInTheDocument()
    const table = await screen.findByRole("table", { name: "Clients" })
    expect(within(table).getByText("2")).toBeInTheDocument() // urgent alerts
    expect(screen.getByRole("table", { name: "Open alerts across clients" })).toHaveTextContent("Mailbox rule forwards mail outside")

    await person.click(within(table).getByRole("button", { name: "Globex" }))
    expect(await screen.findByText(/Working in/)).toHaveTextContent(`Working in Globex for ${tenant.name}`)
    expect(activeOrganisation()).toBe(globex.id)
    await waitFor(() =>
      expect(calls.some((call) => call.path === "/api/v1/alerts/summary" && call.headers.get("X-UTDRS-Organisation") === globex.id)).toBe(true),
    )

    await person.click(screen.getByRole("button", { name: `Back to ${tenant.name}` }))
    await waitFor(() => expect(activeOrganisation()).toBeNull())
    expect(screen.queryByText(/Working in/)).not.toBeInTheDocument()
  })

  it("goes back to your own organisation when a client's access is refused", async () => {
    setActiveOrganisation(globex.id)
    mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/msp": overview,
      "GET /api/v1/alerts/summary": (request) =>
        request.headers.get("X-UTDRS-Organisation")
          ? new Response(JSON.stringify({ detail: "Your service provider does not manage that organisation" }), {
              status: 403, headers: { "Content-Type": "application/json", "X-Organisation-Refused": "true" },
            })
          : { total: 0, by_status: {}, open_by_severity: {} },
    })
    render(<Toaster />)
    renderApp("/")
    expect(await screen.findByText("Your service provider does not manage that organisation")).toBeInTheDocument()
    expect(activeOrganisation()).toBeNull()
  })

  it("shows ordinary organisations no clients", async () => {
    mockGateway({ ...shellRoutes(admin), "GET /api/v1/msp": { msp: false, organisation_id: tenant.id, organisation: tenant.name, role_in_clients: null, clients: [] } })
    renderApp("/profile")
    expect(await screen.findAllByText(tenant.name)).not.toHaveLength(0)
    expect(screen.queryByRole("link", { name: "Clients" })).not.toBeInTheDocument()
  })

  it("lets a client's administrators end their provider's access", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/tenants/current": { ...tenant, managed_by: "665f1c2ab1e2c3d4e5f60a09", managed_by_name: "SafeHands IT" },
      "DELETE /api/v1/tenants/current/msp": { ...tenant, managed_by: null, managed_by_name: null },
    })
    const { user: person } = renderApp("/profile")
    expect(await screen.findByText("SafeHands IT")).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "End their access" }))
    await person.click(within(screen.getByRole("dialog")).getByRole("button", { name: "End access" }))
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE" && call.path === "/api/v1/tenants/current/msp")).toBe(true))
    await waitFor(() => expect(screen.queryByText("SafeHands IT")).not.toBeInTheDocument())
  })
})

describe("service providers' team access", () => {
  it("lets administrators limit staff to the clients assigned to them", async () => {
    const staff = [
      { id: "s1", username: "ana", email: "ana@msp.example", role: "analyst", active: true, clients: [] },
      { id: "s2", username: "boss", email: "boss@msp.example", role: "admin", active: true, clients: [] },
    ]
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/msp": { ...overview, staff_access: "assigned" },
      "GET /api/v1/msp/alerts": [],
      "GET /api/v1/msp/staff": staff,
      "PUT /api/v1/msp/staff/s1/clients": { ...staff[0], clients: [globex.id] },
      "PUT /api/v1/msp/staff-access": { staff_access: "all" },
    })
    const { user: person } = renderApp("/clients")
    const list = await screen.findByRole("list", { name: "Staff and their clients" })
    expect(within(list).queryByText("boss")).not.toBeInTheDocument() // administrators always reach every client
    expect(within(list).getByText("No clients yet")).toBeInTheDocument()
    await person.click(within(list).getByRole("button", { name: "Assign clients" }))
    const dialog = screen.getByRole("dialog")
    await person.click(within(dialog).getByRole("checkbox", { name: "Globex" }))
    await person.click(within(dialog).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/msp/staff/s1/clients")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/msp/staff/s1/clients")?.body ?? "{}")).toEqual({ clients: [globex.id] })

    await person.click(screen.getByRole("radio", { name: /Every client/ }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/msp/staff-access")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/msp/staff-access")?.body ?? "{}")).toEqual({ staff_access: "all" })
  })
})
