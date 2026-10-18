import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, fakeToken, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const overview = {
  "GET /api/v1/alerts/": [],
  "GET /api/v1/events/recent/": [],
  "GET /api/v1/health/db": { status: "ok", database: "connected" },
}
const setup = { secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/UTDRS%20(Contoso):ann%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=UTDRS" }
const recovery = { recovery_codes: ["abcd-efgh", "ijkl-mnop", "qrst-uvwx", "yz23-4567", "aaaa-bbbb", "cccc-dddd", "eeee-ffff", "gggg-hhhh", "iiii-jjjj", "kkkk-llll"] }

describe("multi-factor authentication", () => {
  it("asks for a code after the password, and signs in with it", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(user),
      ...overview,
      "POST /api/v1/auth/login": { mfa_required: true, mfa_token: "step-two", access_token: null, token_type: null, user: null },
      "POST /api/v1/auth/login/mfa": (request) =>
        request.clone().json().then((body: { code: string }) =>
          body.code === "123456" ? { access_token: fakeToken(), token_type: "bearer", user } : json({ detail: "That code is not right" }, 401),
        ),
    })
    const { router, user: person } = renderApp("/login", { signedIn: false })
    await person.type(await screen.findByLabelText("Username"), "ann")
    await person.type(screen.getByLabelText("Password"), crypto.randomUUID())
    await person.click(screen.getByRole("button", { name: "Sign in" }))

    const code = await screen.findByLabelText("Authentication code")
    expect(code).toHaveValue("")  // nothing carried over from the username
    await person.type(code, "000000")
    await person.click(screen.getByRole("button", { name: "Verify" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("That code is not right")

    await person.clear(screen.getByLabelText("Authentication code"))
    await person.type(screen.getByLabelText("Authentication code"), "123456")
    await person.click(screen.getByRole("button", { name: "Verify" }))
    await waitFor(() => expect(router.state.location.pathname).toBe("/"))
    const finish = calls.filter((call) => call.path === "/api/v1/auth/login/mfa").at(-1)
    expect(JSON.parse(finish?.body ?? "{}")).toEqual({ mfa_token: "step-two", code: "123456" })
  })

  it("makes someone whose organisation requires MFA set it up before anything else", async () => {
    const { calls } = mockGateway({
      ...shellRoutes({ ...user, mfa_setup_required: true }),
      "POST /api/v1/auth/mfa/setup": setup,
      "POST /api/v1/auth/mfa/confirm": recovery,
    })
    const { user: person } = renderApp("/alerts")
    expect(await screen.findByRole("heading", { name: "Set up multi-factor authentication" })).toBeInTheDocument()
    expect(calls.some((call) => call.path === "/api/v1/alerts/")).toBe(false)  // the app is not reached

    await person.click(screen.getByRole("button", { name: "Set up multi-factor authentication" }))
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument()
    expect(screen.getByText(setup.secret)).toBeInTheDocument()
    await person.type(screen.getByLabelText("Code from the app"), "654321")
    await person.click(screen.getByRole("button", { name: "Turn on" }))
    const codes = await screen.findByRole("list", { name: "Recovery codes" })
    expect(within(codes).getAllByRole("listitem")).toHaveLength(10)
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/auth/mfa/confirm")?.body ?? "{}")).toEqual({ code: "654321" })
  })

  it("lets an administrator require MFA for everyone", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/auth/mfa": { enabled: true, enabled_at: "2026-10-18T06:00:00+00:00", recovery_codes_left: 9, required_by_organisation: false, encryption_available: true },
      "PATCH /api/v1/tenants/current/security": { id: "t1", name: "Contoso", slug: "contoso", status: "active", created_at: "2026-10-18T06:00:00+00:00", updated_at: "2026-10-18T06:00:00+00:00", require_mfa: true },
    })
    const { user: person } = renderApp("/profile")
    expect(await screen.findByText(/9 recovery codes left/)).toBeInTheDocument()
    await person.click(await screen.findByRole("button", { name: "Require" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/tenants/current/security")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/tenants/current/security")?.body ?? "{}")).toEqual({ require_mfa: true })
  })
})

describe("recovery codes", () => {
  it("stay on screen after turning MFA on from the profile, until they are saved", async () => {
    let enabled = false
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/auth/mfa": () => ({ enabled, enabled_at: enabled ? "2026-10-18T06:00:00+00:00" : null, recovery_codes_left: enabled ? 10 : 0,
                                        required_by_organisation: false, encryption_available: true }),
      "POST /api/v1/auth/mfa/setup": setup,
      "POST /api/v1/auth/mfa/confirm": () => {
        enabled = true
        return recovery
      },
    })
    const { user: person } = renderApp("/profile")
    await person.click(await screen.findByRole("button", { name: "Set up" }))
    await person.click(await screen.findByRole("button", { name: "Set up multi-factor authentication" }))
    await person.type(await screen.findByLabelText("Code from the app"), "654321")
    await person.click(screen.getByRole("button", { name: "Turn on" }))
    expect(await screen.findByRole("list", { name: "Recovery codes" })).toBeInTheDocument()
    // Even if something asks for the status again, the codes stay until saved.
    await new Promise((resolve) => setTimeout(resolve, 300))
    expect(screen.getByRole("list", { name: "Recovery codes" })).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "I have saved them" }))
    expect(await screen.findByText(/10 recovery codes left/)).toBeInTheDocument()
    expect(calls.filter((call) => call.path === "/api/v1/auth/mfa").length).toBeGreaterThan(1)
  })
})
