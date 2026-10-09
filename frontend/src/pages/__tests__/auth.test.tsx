import { screen, waitFor } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { fakeToken, shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const overviewRoutes = {
  ...shellRoutes(),
  "GET /api/v1/alerts/": [],
  "GET /api/v1/events/recent/": [],
  "GET /api/v1/health/db": { status: "ok", database: "connected" },
}

describe("signing in", () => {
  it("sends signed-out visitors to the sign-in page", async () => {
    mockGateway({})
    const { router } = renderApp("/alerts", { signedIn: false })
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe("/login")
  })

  it("signs in with a form-encoded request and returns to the page asked for", async () => {
    const password = crypto.randomUUID()
    const { calls } = mockGateway({
      ...overviewRoutes,
      "POST /api/v1/auth/login": { access_token: fakeToken(), token_type: "bearer", user },
    })
    const { router, user: person } = renderApp("/alerts", { signedIn: false })

    await person.type(await screen.findByLabelText("Username"), "ann")
    await person.type(screen.getByLabelText("Password"), password)
    await person.click(screen.getByRole("button", { name: "Sign in" }))

    await waitFor(() => expect(router.state.location.pathname).toBe("/alerts"))
    const login = calls.find((call) => call.path === "/api/v1/auth/login")
    expect(new URLSearchParams(login?.body)).toEqual(new URLSearchParams({ username: "ann", password, scope: "" }))
    // Later requests carry the token.
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/alerts/")).toBe(true))
  })

  it("shows the gateway's error for wrong credentials", async () => {
    mockGateway({ "POST /api/v1/auth/login": json({ detail: "Incorrect username or password" }, 401) })
    const { user: person } = renderApp("/login", { signedIn: false })
    await person.type(await screen.findByLabelText("Username"), "ann")
    await person.type(screen.getByLabelText("Password"), crypto.randomUUID())
    await person.click(screen.getByRole("button", { name: "Sign in" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect username or password")
  })

  it("signs out when the gateway rejects the session", async () => {
    mockGateway({ ...overviewRoutes, "GET /api/v1/auth/me": json({ detail: "Could not validate credentials" }, 401) })
    const { router } = renderApp("/")
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"))
    expect(await screen.findByText(/session has ended/i)).toBeInTheDocument()
    expect(sessionStorage.length).toBe(0)
  })
})
