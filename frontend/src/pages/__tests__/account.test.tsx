import { screen, waitFor } from "@testing-library/react"
import { describe, expect, it } from "vitest"

import { shellRoutes, user } from "@/test/fixtures"
import { json, mockGateway } from "@/test/gateway"
import { renderApp } from "@/test/render"

const overview = {
  "GET /api/v1/alerts/": [],
  "GET /api/v1/events/recent/": [],
  "GET /api/v1/health/db": { status: "ok", database: "connected" },
}

describe("account emails", () => {
  it("asks for a reset link from the sign-in page", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(),
      "POST /api/v1/auth/forgot-password": json({ message: "If that account exists and has an email address, a link is on its way." }, 202),
    })
    const { user: person, router } = renderApp("/login", { signedIn: false })
    await person.click(await screen.findByRole("link", { name: "Forgot your password?" }))
    expect(router.state.location.pathname).toBe("/forgot-password")
    await person.type(screen.getByLabelText("Username or email address"), "ann@example.com")
    await person.click(screen.getByRole("button", { name: "Email me a link" }))
    expect(await screen.findByText(/a link is on its way/)).toBeInTheDocument()
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/forgot-password"))?.body ?? "{}")).toEqual({ login: "ann@example.com" })
  })

  it("chooses a new password with the token from the link", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(),
      "POST /api/v1/auth/reset-password": { message: "Your password has been changed. Sign in with it." },
    })
    const { user: person } = renderApp("/reset-password#token=the-token-from-the-email", { signedIn: false })
    const password = crypto.randomUUID()
    await person.type(await screen.findByLabelText(/^New password/), password)
    await person.type(screen.getByLabelText(/^Confirm new password/), password)
    await person.click(screen.getByRole("button", { name: "Change password" }))
    expect(await screen.findByText(/Your password has been changed/)).toBeInTheDocument()
    const sent = JSON.parse(calls.find((call) => call.path.endsWith("/reset-password"))?.body ?? "{}")
    expect(sent).toEqual({ token: "the-token-from-the-email", new_password: password })
  })

  it("explains an expired reset link", async () => {
    mockGateway({
      ...shellRoutes(),
      "POST /api/v1/auth/reset-password": json({ detail: "This link has expired or has already been used. Ask for a new one." }, 400),
    })
    const { user: person } = renderApp("/reset-password#token=old-token-value", { signedIn: false })
    await person.type(await screen.findByLabelText(/^New password/), "abcdefgh1")
    await person.type(screen.getByLabelText(/^Confirm new password/), "abcdefgh1")
    await person.click(screen.getByRole("button", { name: "Change password" }))
    expect(await screen.findByText(/has expired or has already been used/)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Ask for a new link" })).toBeInTheDocument()
  })

  it("confirms an email address once, from the link", async () => {
    const { calls } = mockGateway({ ...shellRoutes(), "POST /api/v1/auth/verify-email": { message: "Your email address is confirmed." } })
    renderApp("/verify-email#token=verify-token-value", { signedIn: false })
    expect(await screen.findByText("Your email address is confirmed.")).toBeInTheDocument()
    expect(calls.filter((call) => call.path.endsWith("/verify-email"))).toHaveLength(1)
  })

  it("offers to send the confirmation link again when sign-in needs it", async () => {
    const { calls } = mockGateway({
      ...shellRoutes(),
      "POST /api/v1/auth/login": json({ detail: "Confirm your email address first, with the link we sent you" }, 403),
      "POST /api/v1/auth/resend-verification": json({ message: "sent" }, 202),
    })
    const { user: person } = renderApp("/login", { signedIn: false })
    await person.type(await screen.findByLabelText("Username"), "ann")
    await person.type(screen.getByLabelText("Password"), crypto.randomUUID())
    await person.click(screen.getByRole("button", { name: "Sign in" }))
    await person.click(await screen.findByRole("button", { name: "Send the link again" }))
    expect(await screen.findByText(/A new link is on its way/)).toBeInTheDocument()
    expect(JSON.parse(calls.find((call) => call.path.endsWith("/resend-verification"))?.body ?? "{}")).toEqual({ login: "ann" })
  })

  it("asks someone signed in to confirm their address", async () => {
    const { calls } = mockGateway({
      ...shellRoutes({ ...user, email_verified: false }),
      ...overview,
      "POST /api/v1/auth/me/send-verification": json({ message: "A link is on its way to ann@example.com." }, 202),
    })
    const { user: person } = renderApp("/")
    await person.click(await screen.findByRole("button", { name: "Send the link again" }))
    expect(await screen.findByText("A link is on its way to ann@example.com.")).toBeInTheDocument()
    await waitFor(() => expect(calls.some((call) => call.path.endsWith("/me/send-verification"))).toBe(true))
  })
})
