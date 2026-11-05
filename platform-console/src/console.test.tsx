import { screen, waitFor, within } from "@testing-library/react"
import { afterEach, describe, expect, it } from "vitest"

import { forgetSession } from "@/api/client"
import { json, mockGateway } from "@/test/gateway"
import { renderConsole } from "@/test/render"

const now = "2026-11-06T06:00:00+00:00"
const me = { id: "op1", username: "ops", email: "ops@operators.example", active: true, mfa: true, must_change_password: false, created_at: now, last_sign_in: now }
const acme = {
  id: "665f1c2ab1e2c3d4e5f60a01", name: "Acme", slug: "acme", status: "active", created_at: now, default: false, people: 3, administrators: 1,
  events_last_week: 1200, open_alerts: 4, connectors: 2, last_sign_in: now, mfa_required: false, urgent_alerts: 1, msp: false, managed_by: null, managed_by_name: null,
}
const signed = (extra = {}) => ({ access_token: "operator-token", token_type: "bearer", expires_in: 600, operator: me, ...extra })

afterEach(() => forgetSession())

describe("operator console", () => {
  it("signs in with a password and, the first time, sets up an authenticator", async () => {
    const { calls } = mockGateway({
      "POST /api/v1/platform/auth/login": { step: "enrol", step_token: "step-1", secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/UTDRS%20platform:ops?secret=JBSWY3DPEHPK3PXP" },
      "POST /api/v1/platform/auth/enrol": signed({ recovery_codes: ["aaaa-bbbb", "cccc-dddd"] }),
      "GET /api/v1/platform/auth/me": me,
      "GET /api/v1/platform/organisations": [acme],
    })
    const { user } = renderConsole("/", { signedIn: false })
    await user.type(await screen.findByLabelText(/^Username/), "ops")
    await user.type(screen.getByLabelText(/^Password/), "a-long-operator-password")
    await user.click(screen.getByRole("button", { name: "Continue" }))
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument()
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument()
    await user.type(screen.getByLabelText(/^Code from your authenticator/), "123456")
    await user.click(screen.getByRole("button", { name: "Confirm and sign in" }))
    expect(await screen.findByRole("list", { name: "Recovery codes" })).toHaveTextContent("aaaa-bbbb")
    await user.click(screen.getByRole("button", { name: "I have kept them" }))
    expect(await screen.findByRole("table", { name: "Organisations" })).toHaveTextContent("Acme")
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/platform/auth/enrol")?.body ?? "{}")).toEqual({ step_token: "step-1", code: "123456" })
    const listed = calls.find((call) => call.path === "/api/v1/platform/organisations")
    expect(listed?.headers.get("Authorization")).toBe("Bearer operator-token")
  })

  it("asks for a code on later sign-ins, and says what went wrong", async () => {
    mockGateway({
      "POST /api/v1/platform/auth/login": { step: "mfa", step_token: "step-2" },
      "POST /api/v1/platform/auth/mfa": (request) =>
        request.clone().json().then((body: { code: string }) => (body.code === "654321" ? signed() : json({ detail: "That code is not right" }, 401))),
      "GET /api/v1/platform/auth/me": me,
      "GET /api/v1/platform/organisations": [],
    })
    const { user } = renderConsole("/", { signedIn: false })
    await user.type(await screen.findByLabelText(/^Username/), "ops")
    await user.type(screen.getByLabelText(/^Password/), "a-long-operator-password")
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await user.type(await screen.findByLabelText(/^Code/), "111111")
    await user.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("That code is not right")
    await user.clear(screen.getByLabelText(/^Code/))
    await user.type(screen.getByLabelText(/^Code/), "654321")
    await user.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByText("No organisations yet")).toBeInTheDocument()
  })

  it("makes a temporary password be changed before anything else", async () => {
    const { calls } = mockGateway({ "GET /api/v1/platform/auth/me": { ...me, must_change_password: true }, "POST /api/v1/platform/auth/password": new Response(null, { status: 204 }) })
    const { user } = renderConsole("/")
    expect(await screen.findByText("Choose your password")).toBeInTheDocument()
    expect(screen.queryByRole("navigation", { name: "Main" })).not.toBeInTheDocument()
    await user.type(screen.getByLabelText(/^Current/), "temporary-one")
    await user.type(screen.getByLabelText(/^New password\s*\*?$/), "my-own-long-password")
    await user.type(screen.getByLabelText(/^New password again/), "my-own-long-password")
    await user.click(screen.getByRole("button", { name: "Save and continue" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/platform/auth/password")).toBe(true))
  })

  it("goes back to sign-in, saying why, when the session ends", async () => {
    mockGateway({
      "GET /api/v1/platform/auth/me": me,
      "GET /api/v1/platform/organisations": json({ detail: "Your session ended after a while without use; sign in again" }, 401),
    })
    renderConsole("/")
    expect(await screen.findByText("Your session ended after a while without use; sign in again")).toBeInTheDocument()
    expect(await screen.findByRole("button", { name: "Continue" })).toBeInTheDocument()
  })

  it("manages other operators, but never yourself", async () => {
    const other = { ...me, id: "op2", username: "kim", email: "kim@operators.example" }
    const { calls } = mockGateway({
      "GET /api/v1/platform/auth/me": me,
      "GET /api/v1/platform/operators": [me, other],
      "POST /api/v1/platform/operators/op2/reset": { operator: { ...other, mfa: false, must_change_password: true }, temporary_password: "temp-xyz" },
    })
    const { user } = renderConsole("/operators")
    const table = await screen.findByRole("table", { name: "Operators" })
    const rows = within(table).getAllByRole("row")
    expect(within(rows[1]!).queryByRole("button")).not.toBeInTheDocument() // you
    await user.click(within(rows[2]!).getByRole("button", { name: "Reset" }))
    expect(await screen.findByText("temp-xyz")).toBeInTheDocument()
    expect(calls.some((call) => call.method === "POST" && call.path === "/api/v1/platform/operators/op2/reset")).toBe(true)
  })
})
