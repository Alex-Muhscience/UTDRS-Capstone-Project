import { screen, waitFor } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { admin, event, shellRoutes } from "@/test/fixtures"
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

  it("analyses a failed event again", async () => {
    let analysis: Record<string, unknown> = { status: "error", error: "engine unavailable" }
    const { calls } = mockGateway({
      ...shellRoutes(),
      [`GET /api/v1/events/${ID}`]: () => event({ metadata: { analysis } }),
      [`POST /api/v1/events/${ID}/reanalyse`]: () => {
        analysis = { status: "clean" }
        return event({ metadata: { analysis: { status: "queued", attempts: 0 } } })
      },
    })
    const { user: person } = renderApp(`/events/${ID}`)
    await person.click(await screen.findByRole("button", { name: /Analyse again/ }))
    expect(await screen.findByText("No threat detected")).toBeInTheDocument()
    expect(calls.some((call) => call.method === "POST" && call.path.endsWith("/reanalyse"))).toBe(true)
  })

  it("says the gateway keeps trying while the engine is unavailable", async () => {
    mockGateway({
      ...shellRoutes(),
      [`GET /api/v1/events/${ID}`]: event({ metadata: { analysis: { status: "queued", attempts: 2, error: "The core engine answered 503" } } }),
    })
    renderApp(`/events/${ID}`)
    expect(await screen.findByText("Waiting for the core engine")).toBeInTheDocument()
    expect(screen.getByText(/nothing is lost/)).toBeInTheDocument()
  })

  it("tells administrators about failed analyses and replays them", async () => {
    const detection = shellRoutes(admin)["GET /api/v1/detection/"]
    let failed = 3
    const { calls } = mockGateway({
      ...shellRoutes(admin),
      "GET /api/v1/events/": [],
      "GET /api/v1/detection/": () => ({ ...detection, analysis: { waiting: 0, oldest_waiting_since: null, failed_last_day: failed } }),
      "POST /api/v1/events/reanalyse": () => {
        failed = 0
        return { queued: 3 }
      },
    })
    const { user: person } = renderApp("/events")
    expect(await screen.findByText(/3 events could not be analysed/)).toBeInTheDocument()
    await person.click(screen.getByRole("button", { name: "Analyse them again" }))
    await waitFor(() => expect(screen.queryByText(/could not be analysed/)).not.toBeInTheDocument())
    expect(calls.some((call) => call.path === "/api/v1/events/reanalyse")).toBe(true)
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
