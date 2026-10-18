import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { alert, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

describe("checking an email", () => {
  it("sends the recipient and message id, and opens the alert when it looks malicious", async () => {
    const found = alert()
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/events/": [],
      "POST /api/v1/email/check": { event_id: "665f1c2ab1e2c3d4e5f60201", alert_id: found.id, already_checked: false },
      [`GET /api/v1/alerts/${found.id}`]: found,
    })
    const { user: person } = renderApp("/events")
    await person.click(await screen.findByRole("button", { name: "Check an email" }))
    const dialog = screen.getByRole("dialog")
    await person.type(within(dialog).getByLabelText(/Recipient/), "ana@contoso.example")
    await person.type(within(dialog).getByLabelText(/Message ID/), "<phish-001@mail.evil.example>")
    await person.click(within(dialog).getByRole("button", { name: "Check" }))
    await waitFor(() => expect(calls.some((call) => call.path === "/api/v1/email/check")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/email/check")?.body ?? "{}")).toEqual({
      recipient: "ana@contoso.example",
      internet_message_id: "<phish-001@mail.evil.example>",
    })
    expect(await screen.findByRole("heading", { name: found.title })).toBeInTheDocument()
  })
})
