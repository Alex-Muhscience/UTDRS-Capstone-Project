import { describe, expect, it } from "vitest"

import { fakeToken } from "@/test/fixtures"

import { clearSession, readSession, saveSession, tokenExpiry } from "./session"

describe("tokenExpiry", () => {
  it("reads the exp claim in milliseconds", () => {
    const expiry = tokenExpiry(fakeToken(60))
    expect(expiry).toBeGreaterThan(Date.now())
    expect(expiry).toBeLessThanOrEqual(Date.now() + 61_000)
  })

  it("returns null for malformed tokens", () => {
    expect(tokenExpiry("not-a-jwt")).toBeNull()
    expect(tokenExpiry("a.%%%.c")).toBeNull()
  })
})

describe("session storage", () => {
  it("round-trips a valid session", () => {
    const token = fakeToken()
    saveSession(token)
    expect(readSession()?.token).toBe(token)
    clearSession()
    expect(readSession()).toBeNull()
  })

  it("drops an expired session", () => {
    saveSession(fakeToken(-10))
    expect(readSession()).toBeNull()
    expect(sessionStorage.length).toBe(0)
  })
})
