import { render, screen, waitFor } from "@testing-library/react"
import { Toaster } from "sonner"
import { describe, expect, it } from "vitest"

import { shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

import { parseEvents } from "./live"

describe("parseEvents", () => {
  it("reads complete events and keeps the rest for later", () => {
    const { messages, rest } = parseEvents(
      'retry: 5000\n\nevent: ready\ndata: {}\n\n: keep-alive\n\nid: 1\nevent: alert.created\ndata: {"id":"a1","severity":"high"}\n\nid: 2\nevent: case',
    )
    expect(messages).toEqual([
      { id: null, event: "ready", data: {} },
      { id: "1", event: "alert.created", data: { id: "a1", severity: "high" } },
    ])
    expect(rest).toBe("id: 2\nevent: case")
  })
})

/** A stream that sends "ready", then these events a moment later, and stays open, as the gateway's does. */
function stream(text: string): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("event: ready\ndata: {}\n\n"))
      setTimeout(() => controller.enqueue(new TextEncoder().encode(text)), 300)
    },
  })
  return new Response(body, { headers: { "Content-Type": "text/event-stream" } })
}

describe("live updates", () => {
  it("announces a serious new alert and fetches the alerts again at once", async () => {
    let alertFetches = 0
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/alerts/": () => {
        alertFetches += 1
        return []
      },
      "GET /api/v1/live": (request) =>
        request.headers.get("Last-Event-ID")
          ? json({ detail: "gone" }, 404)
          : stream(
              'id: 665f1c2ab1e2c3d4e5f60c01\nevent: alert.created\ndata: {"id":"665f1c2ab1e2c3d4e5f60c01","title":"Ransomware on FIN-07","severity":"critical"}\n\n',
            ),
    })
    render(<Toaster />)
    renderApp("/alerts")
    expect(await screen.findByText("New critical alert")).toBeInTheDocument()
    expect(screen.getByText("Ransomware on FIN-07")).toBeInTheDocument()
    expect(await screen.findByText("· Live")).toBeInTheDocument()
    await waitFor(() => expect(alertFetches).toBeGreaterThanOrEqual(2))
    const live = calls.find((call) => call.path === "/api/v1/live")
    expect(live).toBeDefined()
    expect(live?.url.search).toBe("") // the token goes in a header, never the address
  })

  it("carries on polling when the gateway has no stream", async () => {
    mockGateway({ ...shellRoutes(user), "GET /api/v1/alerts/": [] })
    renderApp("/alerts")
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument()
    expect(screen.queryByText("· Live")).not.toBeInTheDocument()
  })
})
