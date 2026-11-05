import { act, screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { api, unwrap } from "@/api/client"
import { saveSession } from "@/auth/session"
import { admin, fakeToken, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = new Date().toISOString()
const here = { id: "665f1c2ab1e2c3d4e5f60101", device: "Firefox on Linux", address: "203.0.113.7", created_at: now, last_used_at: now, expires_at: now, mfa: null, current: true }
const phone = { ...here, id: "665f1c2ab1e2c3d4e5f60102", device: "Safari on iPhone", address: "198.51.100.4", current: false }
const overview = {
  "GET /api/v1/alerts/": [],
  "GET /api/v1/events/recent/": [],
  "GET /api/v1/health/db": { status: "ok", database: "connected" },
}

describe("sessions", () => {
  it("refreshes an expiring access token once, however many requests are waiting", async () => {
    const fresh = fakeToken(900)
    const { calls } = mockGateway({
      ...shellRoutes(user),
      ...overview,
      "POST /api/v1/auth/refresh": { access_token: fresh, refresh_token: "second", token_type: "bearer", user, expires_in: 900 },
    })
    saveSession(fakeToken(5), "first")
    renderApp("/", { signedIn: false })
    expect(await screen.findByRole("heading", { name: /Welcome back/ })).toBeInTheDocument()

    const refreshes = calls.filter((call) => call.path === "/api/v1/auth/refresh")
    expect(refreshes).toHaveLength(1)
    expect(JSON.parse(refreshes[0]?.body ?? "{}")).toEqual({ refresh_token: "first" })
    const requests = (vi.mocked(fetch).mock.calls as unknown as Array<[Request]>).map(([request]) => request)
    const me = requests.find((request) => new URL(request.url).pathname === "/api/v1/auth/me")
    expect(me?.headers.get("Authorization")).toBe(`Bearer ${fresh}`)
    expect(JSON.parse(sessionStorage.getItem("utdrs-session") ?? "{}")).toMatchObject({ token: fresh, refreshToken: "second" })
  })

  it("signs out with the gateway's reason when the session cannot be refreshed", async () => {
    mockGateway({
      ...shellRoutes(user),
      ...overview,
      "POST /api/v1/auth/refresh": json({ detail: "Your session reached its time limit: sign in again" }, 401),
    })
    saveSession(fakeToken(5), "first")
    const { router } = renderApp("/", { signedIn: false })
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"))
    expect(await screen.findByText("Your session reached its time limit. Sign in again to continue.")).toBeInTheDocument()
  })

  it("ends the session at the gateway when signing out", async () => {
    const { calls } = mockGateway({ ...shellRoutes(user), ...overview, "POST /api/v1/auth/logout": new Response(null, { status: 204 }) })
    const { router, user: person } = renderApp("/")
    await person.click(await screen.findByRole("button", { name: /Sign out/ }))
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"))
    const logout = (vi.mocked(fetch).mock.calls as unknown as Array<[Request]>).map(([r]) => r).find((r) => r.url.endsWith("/auth/logout"))
    expect(logout?.headers.get("Authorization")).toMatch(/^Bearer /)
    expect(calls.some((call) => call.path === "/api/v1/auth/logout")).toBe(true)
    // Nothing is sent with the old session afterwards.
    await expect(unwrap(api.GET("/api/v1/health"))).rejects.toBeTruthy()
    expect(calls.at(-1)?.path).toBe("/api/v1/health")
  })

  it("signs out after the organisation's idle time", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      mockGateway({
        ...shellRoutes(user),
        ...overview,
        "GET /api/v1/auth/config": { allow_registration: false, registration_mode: "join", session_idle_minutes: 15 },
        "POST /api/v1/auth/logout": new Response(null, { status: 204 }),
      })
      const { router } = renderApp("/")
      expect(await screen.findByRole("heading", { name: /Welcome back/ })).toBeInTheDocument()
      await act(() => vi.advanceTimersByTimeAsync(10 * 60_000))
      expect(router.state.location.pathname).toBe("/")
      await act(() => vi.advanceTimersByTimeAsync(6 * 60_000))
      await waitFor(() => expect(router.state.location.pathname).toBe("/login"))
      expect(await screen.findByText(/signed out after a period of inactivity/)).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it("lists where you are signed in and signs out the others", async () => {
    let sessions = [here, phone]
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/auth/sessions": () => sessions,
      "DELETE /api/v1/auth/sessions/665f1c2ab1e2c3d4e5f60102": () => {
        sessions = [here]
        return new Response(null, { status: 204 })
      },
      "POST /api/v1/auth/sessions/end-others": { ended: 0 },
      "GET /api/v1/notifications/preferences": { channels: {}, minimum_severity: "high" },
      "GET /api/v1/auth/mfa": { enabled: false, enabled_at: null, recovery_codes_left: 0, required_by_organisation: false, encryption_available: true },
    })
    const { user: person } = renderApp("/profile")
    const card = (await screen.findByRole("heading", { name: "Sessions" })).closest("section") as HTMLElement
    expect(await within(card).findByText("Safari on iPhone")).toBeInTheDocument()
    expect(within(card).getByText("This session")).toBeInTheDocument()
    expect(within(card).getByText(/198\.51\.100\.4/)).toBeInTheDocument()

    await person.click(within(card).getByRole("button", { name: "Sign out Safari on iPhone" }))
    await waitFor(() => expect(within(card).queryByText("Safari on iPhone")).not.toBeInTheDocument())
    expect(calls.some((call) => call.method === "DELETE" && call.path.endsWith(phone.id))).toBe(true)
    expect(within(card).queryByRole("button", { name: "Sign out everywhere else" })).not.toBeInTheDocument()
  })

  it("lets an administrator sign someone out everywhere", async () => {
    const { calls } = mockGateway({ ...shellRoutes(admin), [`POST /api/v1/users/${user.id}/sign-out`]: { ended: 2 } })
    const { user: person } = renderApp("/users")
    const table = await screen.findByRole("table", { name: "Users" })
    const row = within(table).getByText("Ann Analyst").closest("tr")!
    await person.click(within(row).getByRole("button", { name: "Sign out everywhere" }))
    await waitFor(() => expect(calls.some((call) => call.path === `/api/v1/users/${user.id}/sign-out`)).toBe(true))
  })
})
