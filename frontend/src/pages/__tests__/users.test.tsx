import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, alert, colleague, event, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

describe("what analysts can do", () => {
  it("hides administration from analysts", async () => {
    mockGateway({ ...shellRoutes(user), "GET /api/v1/detection/rules": [] })
    renderApp("/rules")
    expect(await screen.findByRole("heading", { name: "Detection rules" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /New rule/ })).not.toBeInTheDocument()
    const nav = screen.getByRole("navigation", { name: "Main" })
    expect(within(nav).queryByRole("link", { name: "Users" })).not.toBeInTheDocument()
  })

  it("shows rule status without letting analysts change it", async () => {
    mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/detection/rules": [
        {
          id: "665f1c2ab1e2c3d4e5f60301",
          name: "vpn-brute-force",
          description: "Many failed logins",
          rule_type: "signature",
          detection_source: "identity",
          severity: "high",
          status: "enabled",
          tags: [],
          logic: "x",
          created_at: user.createdAt,
          updated_at: user.createdAt,
          performance_metrics: {},
          metadata: {},
        },
      ],
    })
    renderApp("/rules")
    expect(await screen.findByText("vpn-brute-force")).toBeInTheDocument()
    expect(screen.queryByRole("combobox", { name: /Status of/ })).not.toBeInTheDocument()
    expect(within(screen.getByRole("table", { name: "Detection rules" })).getByText("Enabled")).toBeInTheDocument()
  })

  it("treats the users page as not found", async () => {
    mockGateway(shellRoutes(user))
    renderApp("/users")
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument()
  })
})

describe("user administration", () => {
  it("lists users and changes a role", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      [`PATCH /api/v1/users/${colleague.id}`]: { ...colleague, role: "admin" },
    })
    const { user: person } = renderApp("/users")

    const table = await screen.findByRole("table", { name: "Users" })
    expect(within(table).getByText("Ben Okoth")).toBeInTheDocument()
    // Your own role cannot be changed here.
    expect(within(table).getByRole("combobox", { name: "Role of Ada Admin" })).toBeDisabled()

    await person.selectOptions(within(table).getByRole("combobox", { name: "Role of Ben Okoth" }), "admin")
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ role: "admin" })
  })

  it("shows a reset password once", async () => {
    mockGateway({
      ...shellRoutes(admin),
      [`POST /api/v1/users/${colleague.id}/reset-password`]: { user: colleague, temporary_password: "tmp-Zx81-qa" },
    })
    const { user: person } = renderApp("/users")
    const table = await screen.findByRole("table", { name: "Users" })
    const row = within(table).getByText("Ben Okoth").closest("tr")!
    await person.click(within(row).getByRole("button", { name: /Reset password/ }))
    expect(await screen.findByLabelText("Temporary password")).toHaveTextContent("tmp-Zx81-qa")
  })

  it("adds a user", async () => {
    const created = { ...colleague, id: "665f1c2ab1e2c3d4e5f60009", username: "cara", firstName: "Cara", lastName: null }
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "POST /api/v1/users/": json({ user: created, temporary_password: "tmp-new-1" }, 201),
    })
    const { user: person } = renderApp("/users")
    await person.click(await screen.findByRole("button", { name: /Add user/ }))
    const dialog = screen.getByRole("dialog")
    await person.type(within(dialog).getByLabelText("Username *"), "cara")
    await person.type(within(dialog).getByLabelText("Email *"), "cara@example.com")
    await person.click(within(dialog).getByRole("button", { name: "Add user" }))

    expect(await screen.findByLabelText("Temporary password")).toHaveTextContent("tmp-new-1")
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toMatchObject({
      username: "cara",
      email: "cara@example.com",
      role: "analyst",
    })
  })
})

describe("assignment", () => {
  it("names the assignee and assigns to a colleague", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/alerts/665f1c2ab1e2c3d4e5f60101": alert({ assigned_to: admin.id }),
      "GET /api/v1/events/665f1c2ab1e2c3d4e5f60201": event(),
      "PATCH /api/v1/alerts/665f1c2ab1e2c3d4e5f60101/assign": alert({ assigned_to: colleague.id }),
    })
    const { user: person } = renderApp("/alerts/665f1c2ab1e2c3d4e5f60101")
    expect(await screen.findByText("Assigned to Ada Admin")).toBeInTheDocument()

    await person.selectOptions(screen.getByRole("combobox", { name: "Assign to someone else" }), colleague.id)
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/assign"))).toBe(true))
    expect(calls.find((call) => call.path.endsWith("/assign"))?.url.searchParams.get("assigned_to")).toBe(colleague.id)
  })
})

describe("closed registration", () => {
  it("says accounts come from an administrator", async () => {
    mockGateway({ "GET /api/v1/auth/config": { allow_registration: false } })
    renderApp("/login", { signedIn: false })
    expect(await screen.findByText("Accounts are created by an administrator.")).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /Create an analyst account/ })).not.toBeInTheDocument()
  })

  it("closes the registration page", async () => {
    mockGateway({ "GET /api/v1/auth/config": { allow_registration: false } })
    renderApp("/register", { signedIn: false })
    expect(await screen.findByRole("heading", { name: "Registration is closed" })).toBeInTheDocument()
  })
})
