import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, shellRoutes } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-10-18T06:00:00+00:00"
const hook = {
  id: "665f1c2ab1e2c3d4e5f60b01", name: "Ticketing", url: "https://hooks.example.com/utdrs", events: ["alert.created"], enabled: true,
  created_at: now, created_by: { name: "admin" }, last_delivery_at: now, last_status: "failing",
}
const events = [
  { name: "alert.created", description: "A new alert" },
  { name: "case.created", description: "A new case" },
  { name: "ping", description: "A test" },
]

describe("webhooks", () => {
  it("creates one with the events chosen, and shows its secret once", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/webhooks/": [],
      "GET /api/v1/webhooks/events": events,
      "POST /api/v1/webhooks/": { ...hook, signing_secret: "whsec_abc123" },
    })
    const { user: person } = renderApp("/webhooks")
    await person.click(await screen.findByRole("button", { name: "New webhook" }))
    const dialog = screen.getByRole("dialog")
    expect(within(dialog).queryByText("ping")).not.toBeInTheDocument()
    await person.type(within(dialog).getByLabelText(/^Name/), "Ticketing")
    await person.type(within(dialog).getByLabelText(/^URL/), "https://hooks.example.com/utdrs")
    await person.click(within(dialog).getByRole("checkbox", { name: /case\.created/ }))
    await person.click(within(dialog).getByRole("button", { name: "Create" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}")).toEqual({
      name: "Ticketing",
      url: "https://hooks.example.com/utdrs",
      events: ["case.created"],
    })
    expect(await screen.findByText("whsec_abc123")).toBeInTheDocument()
  })

  it("shows a failing webhook's deliveries and sends one again", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/webhooks/": [hook],
      [`GET /api/v1/webhooks/${hook.id}/deliveries`]: [
        { id: "evt_1", webhook_id: hook.id, event: "alert.created", payload: {}, status: "failed", attempts: 10, response_status: 503,
          error: "The receiver answered 503: down", created_at: now, next_attempt_at: now, delivered_at: null },
      ],
      "POST /api/v1/webhooks/deliveries/evt_1/redeliver": { id: "evt_1", webhook_id: hook.id, event: "alert.created", payload: {}, status: "queued",
                                                            attempts: 0, created_at: now },
    })
    const { user: person } = renderApp("/webhooks")
    expect(await screen.findByText("Failing")).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "Deliveries" }))
    const list = await screen.findByRole("list", { name: "Deliveries" })
    expect(within(list).getByText(/HTTP 503/)).toBeInTheDocument()
    await person.click(within(list).getByRole("button", { name: "Send again" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/redeliver"))).toBe(true))
  })
})
