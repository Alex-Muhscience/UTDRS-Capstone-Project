import { screen, waitFor, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { Microsoft365 } from "@/api/client"
import { admin, shellRoutes } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-18T06:30:00+00:00"
const permissions = [{ name: "AuditLog.Read.All", used_for: "read sign-ins and directory audit logs" }]

function status(overrides: Partial<Microsoft365> = {}): Microsoft365 {
  return { connected: false, last_poll: {}, errors: {}, checks: [], consent_available: false, encryption_available: true, permissions, ...overrides }
}

describe("connectors", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("connects Microsoft 365 with an organisation's own app registration", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/connectors/microsoft-365": status(),
      "PUT /api/v1/connectors/microsoft-365": status({ connected: true, status: "connected" }),
    })
    const { user: person } = renderApp("/connectors")
    expect(await screen.findByText("Not connected")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Connect with Microsoft" })).not.toBeInTheDocument()
    expect(screen.getByText("AuditLog.Read.All")).toBeInTheDocument()

    await person.type(screen.getByLabelText(/Directory \(tenant\) ID/), "72f988bf-86f1-41af-91ab-2d7cd011db47")
    await person.type(screen.getByLabelText(/Application \(client\) ID/), "4a1b2c3d")
    await person.type(screen.getByLabelText(/Client secret/), "s3cret")
    await person.click(screen.getByRole("button", { name: "Connect" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PUT")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PUT")?.body ?? "{}")).toEqual({
      azure_tenant_id: "72f988bf-86f1-41af-91ab-2d7cd011db47",
      client_id: "4a1b2c3d",
      client_secret: "s3cret",
    })
  })

  it("sends an administrator to Microsoft to consent, and finishes when they come back", async () => {
    const assign = vi.fn()
    vi.stubGlobal("location", { ...window.location, origin: "https://utdrs.example", assign })
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/connectors/microsoft-365": status({ consent_available: true }),
      "POST /api/v1/connectors/microsoft-365/consent-url": { url: "https://login.microsoftonline.com/organizations/v2.0/adminconsent?x=1" },
    })
    const { user: person } = renderApp("/connectors")
    await person.click(await screen.findByRole("button", { name: "Connect with Microsoft" }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://login.microsoftonline.com/organizations/v2.0/adminconsent?x=1"))
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/consent-url"))?.body ?? "{}")).toEqual({
      redirect_uri: "https://utdrs.example/connectors/microsoft-365/consented",
    })
  })

  it("finishes consent with what Microsoft sent back", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "POST /api/v1/connectors/microsoft-365/consent": status({ connected: true, status: "connected", mode: "consent" }),
      "GET /api/v1/connectors/microsoft-365": status({ connected: true, status: "connected", mode: "consent" }),
    })
    renderApp("/connectors/microsoft-365/consented?admin_consent=True&tenant=72f988bf&state=abc")
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/consent"))).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/consent"))?.body ?? "{}")).toEqual({
      state: "abc",
      tenant: "72f988bf",
      admin_consent: "True",
      error: null,
      error_description: null,
    })
    expect(calls.filter((call) => call.path.endsWith("/consent"))).toHaveLength(1)
    expect(await screen.findByRole("heading", { name: "Connectors" })).toBeInTheDocument()
  })

  it("shows what a connection brings in, what is wrong, and fetches on demand", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/connectors/microsoft-365": status({
        connected: true,
        status: "error",
        mode: "own_app",
        azure_tenant_id: "72f988bf",
        organisation_name: "Contoso",
        connected_at: now,
        last_poll_at: now,
        last_poll: { signins: 3, audits: 2, alerts: 1 },
        errors: { signins: "Not allowed: check UTDRS's permissions in Microsoft 365" },
        checks: [
          { name: "Signing in", ok: true, detail: "Signed in to tenant 72f988bf" },
          { name: "Sign-ins", ok: false, detail: "Not allowed: needs AuditLog.Read.All, and an Entra ID P1 or P2 licence" },
        ],
      }),
      "POST /api/v1/connectors/microsoft-365/poll": { counts: { signins: 0, audits: 1, alerts: 0 }, errors: {} },
    })
    const { user: person } = renderApp("/connectors")
    expect(await screen.findByText("Needs attention")).toBeInTheDocument()
    expect(screen.getByText("Contoso")).toBeInTheDocument()
    expect(screen.getByText(/3 sign-ins, 2 audit records, 1 Defender alerts/)).toBeInTheDocument()
    expect(screen.getByText("sign-ins: Not allowed: check UTDRS's permissions in Microsoft 365")).toBeInTheDocument()
    const checks = screen.getByRole("list", { name: "What UTDRS can read" })
    expect(within(checks).getByLabelText("Does not work")).toBeInTheDocument()

    await person.click(screen.getByRole("button", { name: "Fetch now" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/poll"))).toBe(true))
  })
})
