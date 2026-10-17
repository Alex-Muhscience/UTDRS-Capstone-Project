import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, fakeToken, shellRoutes, tenant, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

describe("organisations", () => {
  it("names your organisation in the sidebar", async () => {
    mockGateway(shellRoutes(user))
    renderApp("/")
    expect(await screen.findAllByText("Acme Clinic")).not.toHaveLength(0)
  })

  it("lets an administrator rename it", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "PATCH /api/v1/tenants/current": { ...tenant, name: "Acme Health" },
    })
    const { user: person } = renderApp("/profile")
    const card = (await screen.findByRole("heading", { name: "Organisation" })).closest("section")!
    const name = within(card).getByLabelText("Name *")
    await person.clear(name)
    await person.type(name, "Acme Health")
    await person.click(within(card).getByRole("button", { name: "Rename" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ name: "Acme Health" })
  })

  it("shows analysts the name without letting them change it", async () => {
    mockGateway(shellRoutes(user))
    renderApp("/profile")
    const card = (await screen.findByRole("heading", { name: "Organisation" })).closest("section")!
    expect(within(card).getByText("Acme Clinic")).toBeInTheDocument()
    expect(within(card).queryByRole("button", { name: "Rename" })).not.toBeInTheDocument()
  })

  it("asks for the organisation when registering creates one", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/auth/config": { allow_registration: true, registration_mode: "organisation" },
      "POST /api/v1/auth/register": admin,
      "POST /api/v1/auth/login": json({ access_token: fakeToken(), token_type: "bearer", user: admin }),
    })
    const { user: person } = renderApp("/register", { signedIn: false })
    expect(await screen.findByRole("heading", { name: "Create your organisation" })).toBeInTheDocument()
    await person.type(screen.getByLabelText("Organisation *"), "Beta Clinic")
    await person.type(screen.getByLabelText("Username *"), "founder")
    await person.type(screen.getByLabelText("Email *"), "founder@example.com")
    await person.type(screen.getByLabelText("Password *"), "a-long-password")
    await person.click(screen.getByRole("button", { name: "Create account" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/auth/register")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/auth/register")?.body ?? "{}")).toMatchObject({
      organisation: "Beta Clinic",
      username: "founder",
    })
  })
})
