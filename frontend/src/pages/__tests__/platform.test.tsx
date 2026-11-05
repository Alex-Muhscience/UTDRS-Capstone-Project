import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const operator = { ...admin, platform_admin: true }
const now = "2026-11-05T06:00:00+00:00"
const acme = {
  id: "665f1c2ab1e2c3d4e5f60a01", name: "Acme", slug: "acme", status: "active", created_at: now, default: false,
  people: 3, administrators: 1, events_last_week: 1200, open_alerts: 4, connectors: 2, last_sign_in: now, mfa_required: false,
}
const acmeDetail = {
  ...acme,
  users: [{ id: "u1", username: "alice", email: "alice@acme.test", role: "admin", active: true, last_sign_in: now, platform_admin: false, mfa: true },
          { id: "u2", username: "bob", email: "bob@acme.test", role: "viewer", active: true, last_sign_in: null, platform_admin: false, mfa: false }],
}
const consoleRoutes = {
  ...shellRoutes(operator),
  "GET /api/v1/platform/organisations": [acme],
  "GET /api/v1/platform/admins": [{ id: operator.id, username: operator.username, email: operator.email, organisation: "Default", active: true, mfa: true }],
  "GET /api/v1/platform/audit-log": [],
}

describe("platform console", () => {
  it("is only for platform administrators", async () => {
    mockGateway({ ...shellRoutes(admin) })
    renderApp("/platform")
    expect(await screen.findByText(/not found/i)).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: "Platform" })).not.toBeInTheDocument()
  })

  it("explains that the console needs a second factor", async () => {
    mockGateway({
      ...consoleRoutes,
      "GET /api/v1/platform/organisations": json({ detail: "The platform console needs a sign-in with a second factor" }, 403),
    })
    renderApp("/platform")
    expect(await screen.findByText(/needs a sign-in with a second factor/)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Go to your profile" })).toBeInTheDocument()
  })

  it("lists organisations and creates one, showing its administrator's password once", async () => {
    const { calls } = mockGateway({
      ...consoleRoutes,
      "POST /api/v1/platform/organisations": {
        tenant: { ...acmeDetail, id: "665f1c2ab1e2c3d4e5f60a02", name: "Globex" },
        administrator: { id: "u9", username: "hank", email: "hank@globex.test" },
        temporary_password: "temp-Pa55word",
      },
    })
    const { user: person } = renderApp("/platform")
    const table = await screen.findByRole("table", { name: "Organisations" })
    expect(within(table).getByText("Acme")).toBeInTheDocument()
    expect(within(table).getByText("1,200")).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "New organisation" }))
    const dialog = screen.getByRole("dialog")
    await person.type(within(dialog).getByLabelText(/^Organisation name/), "Globex")
    await person.type(within(dialog).getByLabelText(/^Administrator's username/), "hank")
    await person.type(within(dialog).getByLabelText(/^Administrator's email/), "hank@globex.test")
    await person.click(within(dialog).getByRole("button", { name: "Create" }))
    expect(await screen.findByText("temp-Pa55word")).toBeInTheDocument()
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toEqual({
      name: "Globex", admin_username: "hank", admin_email: "hank@globex.test",
    })
  })

  it("suspends an organisation and deletes it only once its name is typed", async () => {
    const { calls } = mockGateway({
      ...consoleRoutes,
      [`GET /api/v1/platform/organisations/${acme.id}`]: acmeDetail,
      [`PATCH /api/v1/platform/organisations/${acme.id}`]: { ...acmeDetail, status: "suspended" },
      [`DELETE /api/v1/platform/organisations/${acme.id}`]: { users: 2 },
    })
    const { user: person } = renderApp(`/platform/organisations/${acme.id}`)
    expect(await screen.findByText("Read-only")).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "Suspend" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ suspended: true })

    await person.click(screen.getByRole("button", { name: "Delete" }))
    const dialog = screen.getByRole("dialog")
    const confirm = within(dialog).getByRole("button", { name: "Delete for good" })
    expect(confirm).toBeDisabled()
    await person.type(within(dialog).getByLabelText(/Type Acme to confirm/), "Acme")
    await person.click(confirm)
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "DELETE")?.body ?? "{}")).toEqual({ confirm_name: "Acme" })
  })

  it("tells read-only people they can look but not change", async () => {
    mockGateway({ ...shellRoutes({ ...user, role: "viewer" }) })
    renderApp("/profile")
    expect(await screen.findByText(/You have read-only access/)).toBeInTheDocument()
  })
})
