import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { admin, fakeToken, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const leaveFor = vi.hoisted(() => vi.fn())
vi.mock("@/lib/navigate", () => ({ leaveFor }))

const overview = {
  "GET /api/v1/alerts/": [],
  "GET /api/v1/events/recent/": [],
  "GET /api/v1/health/db": { status: "ok", database: "connected" },
}
const withSso = (me = user) => {
  const routes = shellRoutes(me)
  return { ...routes, "GET /api/v1/auth/config": { ...(routes["GET /api/v1/auth/config"] as object), sso_available: true } }
}

describe("single sign-on", () => {
  it("sends people to their organisation's provider from the sign-in page", async () => {
    const { calls } = mockGateway({ ...withSso(), "POST /api/v1/auth/sso/start": { url: "https://idp.example/authorize?state=x" } })
    const { user: person } = renderApp("/login", { signedIn: false })
    await person.click(await screen.findByRole("button", { name: "Sign in with SSO" }))
    await person.type(screen.getByLabelText("Work email"), "ann@contoso.com")
    await person.click(screen.getByRole("button", { name: "Continue" }))
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith("https://idp.example/authorize?state=x"))
    const sent = JSON.parse(calls.find((call) => call.path.endsWith("/sso/start"))?.body ?? "{}")
    expect(sent).toEqual({ email: "ann@contoso.com", redirect_uri: `${window.location.origin}/sso/callback` })
  })

  it("signs in when the provider sends them back", async () => {
    const { calls } = mockGateway({
      ...withSso(),
      ...overview,
      "POST /api/v1/auth/sso/callback": { access_token: fakeToken(), refresh_token: "r", token_type: "bearer", user },
    })
    const { router } = renderApp("/sso/callback?code=the-code&state=the-state", { signedIn: false })
    await waitFor(() => expect(router.state.location.pathname).toBe("/"))
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/sso/callback"))?.body ?? "{}")).toEqual({ code: "the-code", state: "the-state" })
  })

  it("says why when the provider or the gateway refuses", async () => {
    mockGateway({ ...withSso() })
    renderApp("/sso/callback?error=access_denied&error_description=The+user+cancelled", { signedIn: false })
    expect(await screen.findByText("The user cancelled")).toBeInTheDocument()
  })

  it("takes people whose organisation requires it to single sign-on", async () => {
    mockGateway({
      ...withSso(),
      "POST /api/v1/auth/login": json({ detail: 'Your organisation signs in with single sign-on: use "Sign in with SSO"' }, 403),
    })
    const { user: person } = renderApp("/login", { signedIn: false })
    await person.type(await screen.findByLabelText("Username"), "ann")
    await person.type(screen.getByLabelText("Password"), crypto.randomUUID())
    await person.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByLabelText("Work email")).toBeInTheDocument()
  })

  it("lets administrators set it up and verify their domain", async () => {
    const pending = {
      configured: true, issuer: "https://login.microsoftonline.com/t/v2.0", client_id: "client", enabled: true, enforce: false,
      auto_provision: false, updated_at: "2026-11-05T10:00:00Z", encryption_available: true,
      domains: [{ domain: "contoso.com", verified: false, record_name: "_utdrs-verification.contoso.com", record_value: "utdrs-verification=abc" }],
    }
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/tenants/current/sso": pending,
      "POST /api/v1/tenants/current/sso/domains/contoso.com/verify": { ...pending, domains: [{ ...pending.domains[0], verified: true }] },
      "PUT /api/v1/tenants/current/sso": pending,
      "GET /api/v1/notifications/preferences": { channels: {}, minimum_severity: "high" },
      "GET /api/v1/auth/mfa": { enabled: false, enabled_at: null, recovery_codes_left: 0, required_by_organisation: false, encryption_available: true },
      "GET /api/v1/auth/sessions": [],
    })
    const { user: person } = renderApp("/profile")
    const card = (await screen.findByRole("heading", { name: "Single sign-on" })).closest("section") as HTMLElement
    expect(await within(card).findByText("_utdrs-verification.contoso.com")).toBeInTheDocument()
    await person.click(within(card).getByRole("button", { name: "Verify contoso.com" }))
    expect(await within(card).findByText("Verified")).toBeInTheDocument()

    await person.click(within(card).getByLabelText(/Require it/))
    await person.click(within(card).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PUT")).toBe(true))
    const saved = JSON.parse(calls.find((call) => call.method === "PUT")?.body ?? "{}")
    expect(saved).toMatchObject({ issuer: pending.issuer, client_id: "client", domains: ["contoso.com"], enabled: true, enforce: true })
    expect(saved.client_secret).toBeUndefined()  // kept as it is
  })
})

describe("provisioning (SCIM)", () => {
  it("makes a token, shown once, and turns it off", async () => {
    let enabled = false
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/tenants/current/sso": { configured: false, domains: [], enabled: false, enforce: false, auto_provision: false, encryption_available: true },
      "GET /api/v1/tenants/current/scim": () => ({ enabled, created_at: enabled ? "2026-11-05T10:00:00Z" : null, last_used_at: null }),
      "POST /api/v1/tenants/current/scim/token": () => {
        enabled = true
        return new Response(JSON.stringify({ token: "utdrs_scim_secret", created_at: "2026-11-05T10:00:00Z" }), { status: 201, headers: { "Content-Type": "application/json" } })
      },
      "DELETE /api/v1/tenants/current/scim/token": () => {
        enabled = false
        return new Response(null, { status: 204 })
      },
      "GET /api/v1/notifications/preferences": { channels: {}, minimum_severity: "high" },
      "GET /api/v1/auth/mfa": { enabled: false, enabled_at: null, recovery_codes_left: 0, required_by_organisation: false, encryption_available: true },
      "GET /api/v1/auth/sessions": [],
      "GET /api/v1/auth/passkeys": [],
    })
    const { user: person } = renderApp("/profile")
    const card = (await screen.findByRole("heading", { name: /Provisioning \(SCIM\)/ })).closest("section") as HTMLElement
    expect(within(card).getByText(/\/api\/v1\/scim\/v2$/)).toBeInTheDocument()
    await person.click(within(card).getByRole("button", { name: "Turn on and make a token" }))
    expect(await within(card).findByLabelText("SCIM token")).toHaveTextContent("utdrs_scim_secret")
    await person.click(within(card).getByRole("button", { name: "Turn off" }))
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE" && call.path.endsWith("/scim/token"))).toBe(true))
    await waitFor(() => expect(within(card).queryByLabelText("SCIM token")).not.toBeInTheDocument())
  })
})
