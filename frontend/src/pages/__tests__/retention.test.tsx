import { screen, waitFor } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, shellRoutes } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const days = { events: 90, alerts: 365, cases: 365, actions: 365, notifications: 90, labels: 730 }

describe("data retention", () => {
  it("changes how long data is kept, sending only what changed, and cleans up on demand", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/retention/": { days, defaults: days, max_days: 730, last_run: { at: "2026-10-18T06:00:00+00:00", deleted: { events: 12, alerts: 3 } } },
      "PATCH /api/v1/retention/": { days: { ...days, events: 30 }, defaults: days, max_days: 730, last_run: null },
      "POST /api/v1/retention/run": { events: 0, alerts: 0, cases: 0, actions: 0, notifications: 0, labels: 0 },
    })
    const { user: person } = renderApp("/retention")
    expect(await screen.findByText("12 deleted")).toBeInTheDocument()
    const events = screen.getByLabelText("Events (days)")
    await person.clear(events)
    await person.type(events, "30")
    await person.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ events: 30 })

    await person.click(screen.getByRole("button", { name: "Clean up now" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/retention/run")).toBe(true))
  })
})
