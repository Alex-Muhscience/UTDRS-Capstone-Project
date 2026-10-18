import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import type { Report } from "@/api/client"
import { admin, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-01T02:00:00+00:00"
const reportId = "665f1c2ab1e2c3d4e5f60901"

function aReport(): Report {
  return {
    id: reportId,
    period: "2026-09",
    generated_at: now,
    generated_by: { type: "schedule", name: "Monthly" },
    data: {
      period: "2026-09",
      title: "September 2026",
      organisation: "Contoso",
      start: "2026-09-01T00:00:00+00:00",
      end: "2026-10-01T00:00:00+00:00",
      headline: ["In September 2026, UTDRS raised 12 alerts, grouped into 4 cases, 1 of them critical.", "1 case is still open, 1 overdue."],
      figures: {
        alerts: { value: 12, previous: 8 },
        cases_opened: { value: 4, previous: 4 },
        critical_cases: { value: 1, previous: 0 },
        cases_closed: { value: 3, previous: 1 },
        actions_taken: { value: 2, previous: 0 },
        median_hours_to_resolve: { value: 3.5, previous: null },
        within_deadline_percent: { value: 75, previous: null },
      },
      alerts_by_severity: { high: 8, critical: 4 },
      weekly_alerts: [
        { start: "2026-09-01T00:00:00+00:00", end: "2026-09-08T00:00:00+00:00", count: 5 },
        { start: "2026-09-08T00:00:00+00:00", end: "2026-09-15T00:00:00+00:00", count: 7 },
      ],
      top_threats: [{ name: "Password guessing (brute force)", count: 6 }],
      most_targeted: [{ type: "user", name: "jsmith", cases: 2 }],
      actions: { taken: 2, automatic: 1, approved: 1, undone: 0, failed: 0, rejected: 0, by_action: [{ label: "Sign out everywhere", count: 2 }] },
      outstanding: {
        open_cases: 1,
        overdue: 1,
        by_priority: { critical: 1 },
        top: [{ id: "665f1c2ab1e2c3d4e5f60501", title: "Shadow copies deleted — fin-ws-07", priority: "critical", due_at: now, overdue: true }],
        awaiting_approval: 0,
      },
      recommendations: ["Deal with the 1 overdue case, starting with \"Shadow copies deleted — fin-ws-07\"."],
    },
  }
}

describe("reports", () => {
  it("lists reports and makes one for a month", async () => {
    const report = aReport()
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/reports/": [{ id: report.id, period: report.period, title: report.data.title, headline: report.data.headline, generated_at: now }],
      "POST /api/v1/reports/": report,
      [`GET /api/v1/reports/${reportId}`]: report,
    })
    const { user: person } = renderApp("/reports")
    expect(await screen.findByRole("link", { name: "September 2026" })).toHaveAttribute("href", `/reports/${reportId}`)
    expect(screen.getByText(/raised 12 alerts, grouped into 4 cases/)).toBeInTheDocument()

    const month = screen.getByLabelText("Month")
    await person.clear(month)
    await person.type(month, "2026-08")
    await person.click(screen.getByRole("button", { name: "Make report" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toEqual({ period: "2026-08" })
    expect(await screen.findByRole("heading", { name: "Security report: September 2026" })).toBeInTheDocument()
  })

  it("shows a report in words and figures, and downloads it as a PDF", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      [`GET /api/v1/reports/${reportId}`]: aReport(),
      [`GET /api/v1/reports/${reportId}/pdf`]: () => new Response(new Blob(["%PDF-1.4"], { type: "application/pdf" }), { headers: { "Content-Type": "application/pdf" } }),
    })
    URL.createObjectURL = vi.fn(() => "blob:report")
    URL.revokeObjectURL = vi.fn()
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {})
    const { user: person } = renderApp(`/reports/${reportId}`)

    expect(await screen.findByText(/Deal with the 1 overdue case/)).toBeInTheDocument()
    const figures = (await screen.findByRole("heading", { name: "The month in figures" })).closest("section") as HTMLElement
    expect(within(figures).getByText("+50% on the month before")).toBeInTheDocument()
    expect(within(figures).getByText("75%")).toBeInTheDocument()
    expect(screen.getByRole("img", { name: "Alerts each week: 5, 7" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Shadow copies deleted — fin-ws-07" })).toHaveAttribute("href", "/cases/665f1c2ab1e2c3d4e5f60501")

    await person.click(screen.getByRole("button", { name: "Download PDF" }))
    await waitFor(() => expect(click).toHaveBeenCalled())
    expect(calls.some((call) => call.path.endsWith("/pdf"))).toBe(true)
    click.mockRestore()
  })
})
