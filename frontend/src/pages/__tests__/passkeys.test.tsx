import { screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { fakeToken, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const overview = {
  "GET /api/v1/alerts/": [],
  "GET /api/v1/events/recent/": [],
  "GET /api/v1/health/db": { status: "ok", database: "connected" },
}
const created = { id: "cred-1", rawId: "cred-1", type: "public-key", response: { clientDataJSON: "e30", attestationObject: "oA" } }
const signed = { id: "cred-1", rawId: "cred-1", type: "public-key", response: { clientDataJSON: "e30", authenticatorData: "AA", signature: "AA" } }
const credentials = { create: vi.fn(), get: vi.fn() }

// jsdom has no WebAuthn: a stand-in browser API, with the JSON helpers browsers now have.
beforeEach(() => {
  vi.stubGlobal("PublicKeyCredential", Object.assign(function PublicKeyCredential() {}, {
    parseCreationOptionsFromJSON: (options: unknown) => options,
    parseRequestOptionsFromJSON: (options: unknown) => options,
  }))
  Object.defineProperty(navigator, "credentials", { value: credentials, configurable: true })
  credentials.create.mockResolvedValue({ toJSON: () => created })
  credentials.get.mockResolvedValue({ toJSON: () => signed })
})
afterEach(() => vi.clearAllMocks())

describe("passkeys", () => {
  it("signs in with a passkey", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(user),
      ...overview,
      "POST /api/v1/auth/passkeys/login/options": { challenge: "abc", rpId: "localhost", userVerification: "required" },
      "POST /api/v1/auth/passkeys/login": { access_token: fakeToken(), refresh_token: "r", token_type: "bearer", user },
    })
    const { user: person, router } = renderApp("/login", { signedIn: false })
    await person.click(await screen.findByRole("button", { name: /Sign in with a passkey/ }))
    await waitFor(() => expect(router.state.location.pathname).toBe("/"))
    expect(credentials.get).toHaveBeenCalledWith({ publicKey: { challenge: "abc", rpId: "localhost", userVerification: "required" } })
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/passkeys/login"))?.body ?? "{}")).toEqual({ credential: signed })
  })

  it("says so when the person cancels", async () => {
    credentials.get.mockRejectedValue(new DOMException("cancelled", "NotAllowedError"))
    mockGateway({ ...shellRoutes(user), "POST /api/v1/auth/passkeys/login/options": { challenge: "abc" } })
    const { user: person } = renderApp("/login", { signedIn: false })
    await person.click(await screen.findByRole("button", { name: /Sign in with a passkey/ }))
    expect(await screen.findByText("The passkey request was cancelled or timed out.")).toBeInTheDocument()
  })

  it("adds and removes passkeys from the profile", async () => {
    let list: unknown[] = []
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/auth/passkeys": () => list,
      "POST /api/v1/auth/passkeys/register/options": { challenge: "xyz", rp: { id: "localhost", name: "UTDRS" } },
      "POST /api/v1/auth/passkeys": () => {
        list = [{ id: "cred-1", name: "Work laptop", created_at: "2026-11-05T10:00:00Z", last_used_at: null, backed_up: true }]
        return new Response(JSON.stringify(list[0]), { status: 201, headers: { "Content-Type": "application/json" } })
      },
      "DELETE /api/v1/auth/passkeys/cred-1": () => {
        list = []
        return new Response(null, { status: 204 })
      },
      "GET /api/v1/notifications/preferences": { channels: {}, minimum_severity: "high" },
      "GET /api/v1/auth/mfa": { enabled: false, enabled_at: null, recovery_codes_left: 0, required_by_organisation: false, encryption_available: true },
      "GET /api/v1/auth/sessions": [],
    })
    const { user: person } = renderApp("/profile")
    const card = (await screen.findByRole("heading", { name: "Passkeys" })).closest("section") as HTMLElement
    await person.type(within(card).getByLabelText(/^Name/), "Work laptop")
    await person.click(within(card).getByRole("button", { name: /Add a passkey/ }))
    expect(await within(card).findByText("Work laptop")).toBeInTheDocument()
    expect(within(card).getByText("Synced")).toBeInTheDocument()
    expect(JSON.parse(calls.find((call) => call.method === "POST" && call.path === "/api/v1/auth/passkeys")?.body ?? "{}")).toEqual({
      credential: created,
      name: "Work laptop",
    })
    await person.click(within(card).getByRole("button", { name: "Remove Work laptop" }))
    await waitFor(() => expect(within(card).queryByText("Work laptop")).not.toBeInTheDocument())
  })
})
