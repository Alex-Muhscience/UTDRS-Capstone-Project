import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, alert, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-09T10:00:00+00:00"

describe("tuning", () => {
  it("records a verdict on an alert and offers to suppress alerts like it", async () => {
    const item = alert({ severity: "medium", title: "Port scan" })
    const marked = { ...item, status: "false_positive", feedback: { verdict: "false_positive", note: "Our scanner", by: { type: "user", name: "ana" }, at: now } }
    const { calls } = mockGateway({
      ...shellRoutes(user),
      [`GET /api/v1/alerts/${item.id}`]: item,
      "GET /api/v1/events/": [],
      [`POST /api/v1/alerts/${item.id}/feedback`]: {
        alert: marked,
        suggestion: { name: "Port scan — 10.0.0.9", detector: "signature:Port scan", entity: { type: "ip", value: "10.0.0.9" }, max_severity: "medium" },
      },
      "POST /api/v1/tuning/suppressions": { id: "s1" },
    })
    const { user: person } = renderApp(`/alerts/${item.id}`)
    await person.type(await screen.findByLabelText("Verdict note"), "Our scanner")
    await person.click(screen.getByRole("button", { name: "False positive" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/feedback"))).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/feedback"))?.body ?? "{}")).toEqual({ verdict: "false_positive", note: "Our scanner" })

    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByText("Suppress alerts like this")).toBeInTheDocument()
    expect(within(dialog).getByLabelText(/^Name/)).toHaveValue("Port scan — 10.0.0.9")
    expect(within(dialog).getByLabelText("Which one")).toHaveValue("10.0.0.9")
    // Analysts cannot suppress critical alerts or suppress for good.
    expect(within(dialog).queryByRole("option", { name: "Everything, even critical" })).not.toBeInTheDocument()
    expect(within(dialog).queryByRole("option", { name: "Never" })).not.toBeInTheDocument()
    await person.type(within(dialog).getByLabelText(/^Why/), "Our vulnerability scanner")
    await person.click(within(dialog).getByRole("button", { name: "Suppress" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/tuning/suppressions" && call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/tuning/suppressions")?.body ?? "{}")).toEqual({
      name: "Port scan — 10.0.0.9",
      reason: "Our vulnerability scanner",
      title_contains: null,
      detector: "signature:Port scan",
      entity: { type: "ip", value: "10.0.0.9" },
      max_severity: "medium",
      expires_in_days: 90,
    })
  })

  it("shows noisy detectors and the suppressions in force", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/tuning/quality": [
        { detector: "signature:DNS tunnelling", name: "DNS tunnelling", alerts: 9, suppressed: 2, true_positive: 1, false_positive: 5, benign: 1, precision: 0.14, noisy: true },
      ],
      "GET /api/v1/tuning/suppressions": [
        {
          id: "665f1c2ab1e2c3d4e5f60a01", name: "Scanner", reason: "Our vulnerability scanner", title_contains: null, detector: null,
          entity: { type: "ip", value: "10.0.0.9" }, max_severity: "high", enabled: true, expires_at: null, hits: 14, last_hit_at: now,
          created_by: { type: "user", name: "admin" }, created_at: now,
        },
      ],
      "PATCH /api/v1/tuning/suppressions/665f1c2ab1e2c3d4e5f60a01": {},
    })
    const { user: person } = renderApp("/tuning")
    const table = await screen.findByRole("table", { name: "Detector quality" })
    expect(within(table).getByText("Noisy")).toBeInTheDocument()
    expect(within(table).getByText("14%")).toBeInTheDocument()
    expect(await screen.findByText("Our vulnerability scanner. Alerts involving address 10.0.0.9, up to high.")).toBeInTheDocument()
    expect(screen.getByText(/14 suppressed/)).toHaveTextContent("never expires")

    await person.click(screen.getByRole("button", { name: "Turn off" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "PATCH")?.body ?? "{}")).toEqual({ enabled: false })
  })
})
