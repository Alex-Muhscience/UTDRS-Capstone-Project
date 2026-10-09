import { describe, expect, it, vi } from "vitest"

import { UNAUTHORIZED_EVENT } from "@/auth/session"
import { json, mockGateway } from "@/test/gateway"

import { api, ApiError, errorMessage, setAuthToken, unwrap } from "./client"

describe("errorMessage", () => {
  it("uses FastAPI's detail string", () => {
    expect(errorMessage({ detail: "Incorrect username or password" }, 401)).toBe("Incorrect username or password")
  })

  it("names the field of the first validation error", () => {
    const error = { detail: [{ loc: ["body", "password"], msg: "Value error, Password must be at least 8 characters long" }] }
    expect(errorMessage(error, 422)).toBe("password: Password must be at least 8 characters long")
  })

  it("explains network failures", () => {
    expect(errorMessage(undefined, 0)).toBe("Cannot reach the API gateway.")
  })
})

describe("unwrap", () => {
  it("returns data and throws ApiError with the gateway's message", async () => {
    mockGateway({
      "GET /api/v1/health": { status: "ok" },
      "PATCH /api/v1/alerts/abc/status": json({ detail: "Invalid status" }, 400),
    })
    await expect(unwrap(api.GET("/api/v1/health"))).resolves.toEqual({ status: "ok" })

    const failure = unwrap(
      api.PATCH("/api/v1/alerts/{alert_id}/status", { params: { path: { alert_id: "abc" }, query: { status: "x" } } }),
    )
    await expect(failure).rejects.toBeInstanceOf(ApiError)
    await expect(failure).rejects.toMatchObject({ status: 400, message: "Invalid status" })
  })

  it("turns a network failure into status 0", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")))
    await expect(unwrap(api.GET("/api/v1/health"))).rejects.toMatchObject({ status: 0 })
  })
})

describe("authentication", () => {
  it("sends the bearer token and reports a rejected one", async () => {
    const { calls } = mockGateway({ "GET /api/v1/auth/me": json({ detail: "Could not validate credentials" }, 401) })
    const onUnauthorized = vi.fn()
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    setAuthToken("token-123")

    await expect(unwrap(api.GET("/api/v1/auth/me"))).rejects.toMatchObject({ status: 401 })

    expect(calls).toHaveLength(1)
    expect(onUnauthorized).toHaveBeenCalledOnce()
    window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    setAuthToken(null)
  })

  it("does not report a failed sign-in as an expired session", async () => {
    mockGateway({ "POST /api/v1/auth/login": json({ detail: "Incorrect username or password" }, 401) })
    const onUnauthorized = vi.fn()
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    await expect(unwrap(api.POST("/api/v1/auth/login", { body: { username: "a", password: "b", scope: "" } }))).rejects.toBeInstanceOf(ApiError)
    expect(onUnauthorized).not.toHaveBeenCalled()
    window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  })
})
