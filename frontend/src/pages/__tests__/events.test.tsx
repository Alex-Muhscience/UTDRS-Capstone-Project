import { screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { event, shellRoutes } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const ID = "665f1c2ab1e2c3d4e5f60201"

describe("event verdicts", () => {
  it("links a threat to the alert it raised", async () => {
    mockGateway({
      ...shellRoutes(),
      [`GET /api/v1/events/${ID}`]: event({ metadata: { analysis: { status: "threat", alert_id: "665f1c2ab1e2c3d4e5f60101" } } }),
    })
    renderApp(`/events/${ID}`)
    expect(await screen.findByText("Threat detected")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /Open the alert/ })).toHaveAttribute("href", "/alerts/665f1c2ab1e2c3d4e5f60101")
  })

  it("explains an event the engine could not analyse", async () => {
    mockGateway({
      ...shellRoutes(),
      [`GET /api/v1/events/${ID}`]: event({ metadata: { analysis: { status: "error", error: "engine unavailable" } } }),
    })
    renderApp(`/events/${ID}`)
    expect(await screen.findByText("Analysis failed")).toBeInTheDocument()
    expect(screen.getByText(/engine unavailable/)).toBeInTheDocument()
  })

  it("says when no engine analysed an older event", async () => {
    mockGateway({ ...shellRoutes(), [`GET /api/v1/events/${ID}`]: event({ created_at: "2020-01-01T00:00:00+00:00" }) })
    renderApp(`/events/${ID}`)
    expect(await screen.findByText("Not analysed")).toBeInTheDocument()
  })

  it("sends a test event from a preset and opens it", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(),
      "GET /api/v1/events/": [],
      "POST /api/v1/events/": event(),
      [`GET /api/v1/events/${ID}`]: event(),
    })
    const { router, user: person } = renderApp("/events")
    await person.click(await screen.findByRole("button", { name: "Send test event" }))
    await person.click(screen.getByRole("button", { name: "Send event" }))

    expect(await screen.findByRole("heading", { name: "Shadow copies deleted" })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe(`/events/${ID}`)
    const sent = JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "{}") as Record<string, unknown>
    expect(sent).toMatchObject({
      event_type: "process",
      raw_data: { command_line: "vssadmin delete shadows /all /quiet" },
    })
  })
})
