import { screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { shellRoutes, user } from "@/test/fixtures"
import { mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const now = "2026-11-05T06:00:00+00:00"
const alertItem = { id: "665f1c2ab1e2c3d4e5f6a001", kind: "alert", title: "New critical alert: Ransomware on FIN-07", body: "", link: "/alerts/665f1c2ab1e2c3d4e5f60c01",
                    severity: "critical", target: { type: "alert", id: "665f1c2ab1e2c3d4e5f60c01" }, created_at: now, read: false }
const assigned = { id: "665f1c2ab1e2c3d4e5f6a002", kind: "case_assigned", title: "Ada assigned you a case: Phishing wave", body: "", link: "/cases/c1",
                   severity: null, target: { type: "case", id: "c1" }, created_at: now, read: true }

describe("notifications centre", () => {
  it("shows unread notifications at the bell, and opening one marks it read", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/inbox/unread": { unread: 1 },
      "GET /api/v1/inbox": { items: [alertItem, assigned], has_more: false, unread: 1 },
      "POST /api/v1/inbox/read": { unread: 0 },
    })
    const { user: person, router } = renderApp("/profile")
    const bell = await screen.findByRole("button", { name: "Notifications, 1 unread" })
    await person.click(bell)
    const panel = screen.getByRole("dialog", { name: "Notifications" })
    expect(await within(panel).findByText("Ada assigned you a case: Phishing wave")).toBeInTheDocument()
    await person.click(within(panel).getByText("New critical alert: Ransomware on FIN-07"))
    await waitFor(() => expect(calls.some((call) => call.method === "POST" && call.path === "/api/v1/inbox/read")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.path === "/api/v1/inbox/read")?.body ?? "{}")).toEqual({ ids: [alertItem.id] })
    expect(router.state.location.pathname).toBe("/alerts/665f1c2ab1e2c3d4e5f60c01")
    expect(await screen.findByRole("button", { name: "Notifications" })).toBeInTheDocument() // none unread now
  })

  it("lists everything, or only what is unread, and marks all read", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(user),
      "GET /api/v1/inbox/unread": { unread: 1 },
      "GET /api/v1/inbox": (_request, url) =>
        url.searchParams.get("unread_only") === "true"
          ? { items: [alertItem], has_more: false, unread: 1 }
          : url.searchParams.get("before")
            ? { items: [{ ...assigned, id: "665f1c2ab1e2c3d4e5f6a000", title: "An older one" }], has_more: false, unread: 1 }
            : { items: [alertItem, assigned], has_more: true, unread: 1 },
      "POST /api/v1/inbox/read": { unread: 0 },
    })
    const { user: person } = renderApp("/inbox")
    const list = await screen.findByRole("list", { name: "Notifications" })
    expect(within(list).getAllByRole("button")).toHaveLength(2)
    await person.click(screen.getByRole("button", { name: "Show older" }))
    expect(await screen.findByText("An older one")).toBeInTheDocument()
    expect(calls.some((call) => call.url.searchParams.get("before") === assigned.id)).toBe(true)

    await person.click(screen.getByRole("button", { name: "Unread (1)" }))
    await waitFor(() => expect(screen.queryByText("Ada assigned you a case: Phishing wave")).not.toBeInTheDocument())
    await person.click(screen.getByRole("button", { name: "Mark all read" }))
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true))
    expect(JSON.parse(calls.find((call) => call.method === "POST")?.body ?? "")).toEqual({})
  })
})
