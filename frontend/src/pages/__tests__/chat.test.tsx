import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, shellRoutes } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-11-06T06:00:00+00:00"
const events = [
  { name: "alert.created", description: "A new alert, from the channel's minimum severity" },
  { name: "case.created", description: "A new case" },
  { name: "action.approval_requested", description: "A response action waiting for a decision" },
  { name: "action.failed", description: "A response action that failed" },
]
const slackApp = {
  id: "665f1c2ab1e2c3d4e5f60d01", name: "SOC", kind: "slack_app", events: ["action.approval_requested"], min_alert_severity: "high", enabled: true,
  slack_channel: "C123", last_status: "failing", last_error: "Slack refused: not_in_channel", last_sent_at: now, created_at: now,
  interactions_url: "https://api.example/api/v1/chat/slack/665f1c2ab1e2c3d4e5f60d01/interactions",
}

describe("Slack and Teams", () => {
  it("adds a Teams channel with the events chosen", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/chat/events": events,
      "GET /api/v1/chat/channels": [],
      "POST /api/v1/chat/channels": { ...slackApp, kind: "teams", name: "Security team", interactions_url: null, last_status: null, last_error: null },
    })
    const { user } = renderApp("/chat")
    await user.click(await screen.findByRole("button", { name: "Add a channel" }))
    const dialog = screen.getByRole("dialog")
    await user.type(within(dialog).getByLabelText(/^Name/), "Security team")
    await user.type(within(dialog).getByLabelText(/^Webhook URL/), "https://prod-01.westeurope.logic.azure.com/workflows/abc")
    await user.click(within(dialog).getByRole("checkbox", { name: /A new case/ }))
    await user.click(within(dialog).getByRole("button", { name: "Add" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toMatchObject({
      name: "Security team",
      kind: "teams",
      webhook_url: "https://prod-01.westeurope.logic.azure.com/workflows/abc",
      events: ["alert.created", "case.created", "action.approval_requested", "action.failed"],
      min_alert_severity: "high",
    })
  })

  it("shows a Slack app's Request URL and why it is failing, and sends a test", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/chat/events": events,
      "GET /api/v1/chat/channels": [slackApp],
      [`POST /api/v1/chat/channels/${slackApp.id}/test`]: new Response(null, { status: 204 }),
    })
    const { user } = renderApp("/chat")
    expect(await screen.findByText("Slack refused: not_in_channel")).toBeInTheDocument()
    expect(screen.getByText(slackApp.interactions_url)).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Send a test" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/test"))).toBe(true))
  })
})
