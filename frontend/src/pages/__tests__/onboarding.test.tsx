import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

function checklist(overrides: { dismissed?: boolean; complete?: boolean } = {}) {
  return {
    steps: [
      { key: "name", title: "Name your organisation", done: true, detail: "Called Contoso", optional: false, attention: false },
      { key: "microsoft_365", title: "Connect Microsoft 365", done: false, detail: "So UTDRS can watch sign-ins", optional: false, attention: false },
      { key: "response", title: "Choose how UTDRS responds", done: false, detail: "Ask before acting, act on its own, or only suggest", optional: false, attention: false },
      { key: "team", title: "Invite your team", done: false, detail: "Add the people who look after security", optional: true, attention: false },
      { key: "email", title: "Check email works", done: false, detail: "Email is not set up on this UTDRS yet (SMTP settings)", optional: true, attention: false },
      { key: "results", title: "See your first results", done: false, detail: "Results appear within minutes of connecting Microsoft 365", optional: false, attention: false },
    ],
    done: 1,
    total: 6,
    complete: false,
    dismissed: false,
    results: { events: 0, sign_ins: 0, alerts: 0, open_cases: 0, reports: 0 },
    ...overrides,
  }
}

describe("onboarding", () => {
  it("shows administrators how far setup has got, on the overview", async () => {
    mockGateway({ ...shellRoutes(admin), "GET /api/v1/onboarding/": checklist() })
    renderApp("/")
    const banner = await screen.findByRole("link", { name: /Finish setting up UTDRS/ })
    expect(banner).toHaveAttribute("href", "/get-started")
    expect(within(banner).getByText("1 of 6 done. Next: connect microsoft 365")).toBeInTheDocument()
  })

  it("does not show the banner to analysts, or once it is put away", async () => {
    mockGateway({ ...shellRoutes(user), "GET /api/v1/onboarding/": checklist() })
    const first = renderApp("/")
    await screen.findByRole("heading", { name: /Welcome back/ })
    expect(screen.queryByText("Finish setting up UTDRS")).not.toBeInTheDocument()
    first.unmount()

    mockGateway({ ...shellRoutes(admin), "GET /api/v1/onboarding/": checklist({ dismissed: true }) })
    renderApp("/")
    await screen.findByRole("heading", { name: /Welcome back/ })
    await waitFor(() => expect(screen.queryByText("Finish setting up UTDRS")).not.toBeInTheDocument())
  })

  it("walks through the steps with their actions", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/onboarding/": checklist(),
      "PATCH /api/v1/response/settings": { mode: "approval", max_actions_per_hour: 20, protected_accounts: [] },
      "PATCH /api/v1/onboarding/": checklist({ dismissed: true }),
    })
    const { user: person } = renderApp("/get-started")
    expect(await screen.findByText("1 of 6 done. Connect Microsoft 365 and UTDRS starts finding threats within minutes.")).toBeInTheDocument()
    expect(screen.getByRole("progressbar", { name: "Setup progress" })).toHaveAttribute("aria-valuenow", "1")
    expect(screen.getByRole("link", { name: "Connect Microsoft 365" })).toHaveAttribute("href", "/connectors")
    // Email is not set up, so there is nothing to test yet.
    expect(screen.queryByRole("button", { name: "Send me a test email" })).not.toBeInTheDocument()

    await person.click(screen.getByRole("button", { name: "Ask before acting" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/response/settings")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/response/settings")?.body ?? "{}")).toEqual({ mode: "approval" })

    await person.click(screen.getByRole("button", { name: "Finish later" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/onboarding/" && call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH" && call.path === "/api/v1/onboarding/")?.body ?? "{}")).toEqual({ dismissed: true })
  })
})
