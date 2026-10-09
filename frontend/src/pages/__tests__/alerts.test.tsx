import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { alert, event, shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

describe("alerts list", () => {
  it("lists alerts and filters by status through the API and the URL", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(),
      "GET /api/v1/alerts/": (_request, url) =>
        url.searchParams.get("status") === "resolved"
          ? [alert({ id: "665f1c2ab1e2c3d4e5f60102", title: "Old phishing alert", status: "resolved" })]
          : [alert()],
    })
    const { router, user: person } = renderApp("/alerts")

    const table = await screen.findByRole("table", { name: "Alerts" })
    expect(within(table).getByText("Potential Ransomware Activity: Recovery Inhibited")).toBeInTheDocument()

    await person.click(screen.getByRole("tab", { name: "Resolved" }))
    expect(await screen.findByText("Old phishing alert")).toBeInTheDocument()
    expect(router.state.location.search).toBe("?status=resolved")
    const last = calls.filter((call) => call.path === "/api/v1/alerts/").at(-1)
    expect(last?.url.searchParams.get("status")).toBe("resolved")
    // One more row than a page, to know whether there is a next page.
    expect(last?.url.searchParams.get("limit")).toBe("26")
  })
})

describe("alert triage", () => {
  const routes = () => ({
    ...shellRoutes(),
    "GET /api/v1/alerts/665f1c2ab1e2c3d4e5f60101": alert(),
    "GET /api/v1/events/665f1c2ab1e2c3d4e5f60201": event({ metadata: { analysis: { status: "threat" } } }),
    "PATCH /api/v1/alerts/665f1c2ab1e2c3d4e5f60101/status": alert({ status: "in_progress" }),
    "PATCH /api/v1/alerts/665f1c2ab1e2c3d4e5f60101/assign": alert({ assigned_to: user.id }),
  })

  it("shows the engine's detection with links to MITRE ATT&CK and the linked event", async () => {
    mockGateway(routes())
    renderApp("/alerts/665f1c2ab1e2c3d4e5f60101")
    expect(await screen.findByRole("link", { name: /T1490/ })).toHaveAttribute(
      "href",
      "https://attack.mitre.org/techniques/T1490/",
    )
    expect(await screen.findByRole("link", { name: /Shadow copies deleted/ })).toHaveAttribute(
      "href",
      "/events/665f1c2ab1e2c3d4e5f60201",
    )
  })

  it("moves the alert to investigating with a note, and assigns it", async () => {
    const { calls } = mockGateway(routes())
    const { user: person } = renderApp("/alerts/665f1c2ab1e2c3d4e5f60101")

    await person.type(await screen.findByLabelText("Note"), "Isolating the laptop")
    await person.click(screen.getByRole("button", { name: "Start investigating" }))
    await waitFor(() => expect(calls.some((call) => call.method === "PATCH" && call.path.endsWith("/status"))).toBe(true))
    const status = calls.find((call) => call.path.endsWith("/status"))
    expect(status?.url.searchParams.get("status")).toBe("in_progress")
    expect(status?.url.searchParams.get("notes")).toBe("Isolating the laptop")

    await person.click(screen.getByRole("button", { name: "Assign to me" }))
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/assign"))).toBe(true))
    expect(calls.find((call) => call.path.endsWith("/assign"))?.url.searchParams.get("assigned_to")).toBe(user.id)
  })
})
