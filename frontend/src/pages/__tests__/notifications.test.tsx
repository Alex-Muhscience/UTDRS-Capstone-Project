import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const preferences = { email: true, new_cases: "high", approvals: true, actions: "failed", email_configured: true, address: "ana@example.com" }

describe("notifications", () => {
  it("saves what you are emailed about as you change it, and sends a test email", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/notifications/preferences": preferences,
      "PATCH /api/v1/notifications/preferences": { ...preferences, new_cases: "critical" },
      "POST /api/v1/notifications/test": { sent: false, error: "The mail server refused it: 554 no" },
    })
    const { user: person } = renderApp("/profile")
    expect(await screen.findByText("Sent to ana@example.com.")).toBeInTheDocument()
    await person.selectOptions(screen.getByLabelText("New cases"), "critical")
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ new_cases: "critical" })

    await person.click(screen.getByRole("button", { name: "Send me a test email" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST" && call.path === "/api/v1/notifications/test")).toBe(true))
  })

  it("says when email is not set up", async () => {
    mockGateway({ ...shellRoutes(user), "GET /api/v1/notifications/preferences": { ...preferences, email_configured: false } })
    renderApp("/profile")
    expect(await screen.findByText(/Email is not set up on this UTDRS yet/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Send me a test email" })).toBeDisabled()
  })

  it("shows administrators what was sent and what was not", async () => {
    const now = "2026-10-09T10:00:00+00:00"
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/notifications/": [
        { id: "n1", kind: "case_opened", user_id: "u1", email: "ana@example.com", subject: "[UTDRS] High case: Shadow copies deleted", link: null, about: null, status: "sent", error: null, attempts: 1, created_at: now, sent_at: now },
        { id: "n2", kind: "approval_needed", user_id: "u2", email: "bo@example.com", subject: "[UTDRS] Approval needed", link: null, about: null, status: "queued", error: "The mail server refused it: 451 later", attempts: 2, created_at: now, sent_at: null },
      ],
    })
    const { user: person } = renderApp("/email-log")
    const table = await screen.findByRole("table", { name: "Email log" })
    expect(within(table).getByText("Sent")).toBeInTheDocument()
    expect(within(table).getByText("Retrying (2)")).toBeInTheDocument()
    expect(within(table).getByText(/Approval needed · The mail server refused it: 451 later/)).toBeInTheDocument()

    await person.selectOptions(screen.getByLabelText("Status"), "failed")
    await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("status") === "failed")).toBe(true))
  })
})
