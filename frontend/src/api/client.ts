import createClient, { type Middleware } from "openapi-fetch"

import { saveSession, tokenExpiry, UNAUTHORIZED_EVENT, type Session } from "@/auth/session"

import { deployedApiUrl } from "./deployment"
import type { components, paths } from "./schema"

export type Schemas = components["schemas"]
export type Alert = Schemas["Alert"]
export type AlertSummary = Schemas["AlertSummary"]
export type Event = Schemas["Event"]
export type EventCreate = Schemas["EventCreate"]
export type Asset = Schemas["Asset"]
export type AssetCreate = Schemas["AssetCreate"]
export type DetectionRule = Schemas["DetectionRule"]
export type DetectionRuleCreate = Schemas["DetectionRuleCreate"]
export type DetectionStatus = Schemas["DetectionStatus"]
export type Simulation = Schemas["Simulation"]
export type SimulationCreate = Schemas["SimulationCreate"]
export type User = Schemas["User"]
export type UserWithPassword = Schemas["UserWithPassword"]
export type ApiKey = Schemas["ApiKey"]
export type ApiKeyWithSecret = Schemas["ApiKeyWithSecret"]
export type AuditEntry = Schemas["AuditEntry"]
export type Case = Schemas["Case"]
export type CaseEvidence = Schemas["CaseEvidence"]
export type Action = Schemas["Action"]
export type ActionType = Schemas["ActionType"]
export type Playbook = Schemas["Playbook"]
export type ResponseSettings = Schemas["ResponseSettings"]
export type NotificationPreferences = Schemas["NotificationPreferences"]
export type Notification = Schemas["Notification"]
export type Report = Schemas["Report"]
export type ReportSummary = Schemas["ReportSummary"]
export type Suppression = Schemas["Suppression"]
export type SuppressionCreate = Schemas["SuppressionCreate"]
export type SuppressionSuggestion = Schemas["SuppressionSuggestion"]
export type DetectorQuality = Schemas["DetectorQuality"]
export type Microsoft365 = Schemas["Microsoft365"]
export type Webhook = Schemas["Webhook"]
export type SessionInfo = Schemas["SessionInfo"]
export type SsoSettings = Schemas["SsoSettings"]
export type OrganisationSummary = Schemas["OrganisationSummary"]
export type OrganisationDetail = Schemas["OrganisationDetail"]
export type PlatformAdmin = Schemas["PlatformAdmin"]
export type CreatedAdministrator = Schemas["CreatedAdministrator"]
export type Delivery = Schemas["Delivery"]
export type Role = Schemas["UserAdminUpdate"]["role"]

/** An error response from the gateway, or a network failure (status 0). */
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

let current: Session | null = null
let refreshing: Promise<Session | null> | null = null
const refreshed = new Set<(session: Session) => void>()

// Refresh this long before the access token expires, so requests never carry an expired one.
const REFRESH_EARLY_MS = 30_000
// Requests that authenticate themselves: never refreshed first, never reported as a lost session.
const SELF_AUTHENTICATED = /\/auth\/(refresh|logout|login|login\/mfa|register|sso\/start|sso\/callback|passkeys\/login|passkeys\/login\/options)$/

/** The session whose tokens are sent with every request; set by the auth provider. */
export function setAuthSession(session: Session | null): void {
  current = session
}

/** Use just an access token (no refresh token): for tests and tools. */
export function setAuthToken(token: string | null): void {
  current = token ? { token, expiresAt: tokenExpiry(token), refreshToken: null } : null
}

/** Called with the new session each time the tokens are refreshed. */
export function onSessionRefreshed(listener: (session: Session) => void): () => void {
  refreshed.add(listener)
  return () => refreshed.delete(listener)
}

function sessionLost(reason?: string): void {
  window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT, { detail: reason }))
}

/**
 * Swap the refresh token for new tokens. Concurrent callers share one request: a refresh
 * token works once, and the gateway ends the session if it sees one used twice.
 */
export function refreshSession(): Promise<Session | null> {
  const refreshToken = current?.refreshToken
  if (!refreshToken) return Promise.resolve(null)
  refreshing ??= (async () => {
    try {
      const { data, error, response } = await api.POST("/api/v1/auth/refresh", { body: { refresh_token: refreshToken } })
      // Signed out meanwhile: keep nothing.
      if (current?.refreshToken !== refreshToken) return null
      if (data?.access_token && data.refresh_token) {
        const next = saveSession(data.access_token, data.refresh_token)
        current = next
        refreshed.forEach((listener) => listener(next))
        return next
      }
      if (response.status === 401) sessionLost(errorMessage(error, 401))
      return null
    } catch {
      return null // The gateway could not be reached: the next request tries again.
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

/** A current access token, refreshed first when it is about to expire; null when signed out. */
export async function accessToken(): Promise<string | null> {
  if (current?.refreshToken && current.expiresAt !== null && current.expiresAt - Date.now() < REFRESH_EARLY_MS) {
    await refreshSession()
  }
  return current?.token ?? null
}

/** End this session at the gateway (best effort), then forget it here. */
export async function endSession(): Promise<void> {
  if (current?.refreshToken && current.expiresAt !== null && current.expiresAt <= Date.now() + REFRESH_EARLY_MS) {
    await refreshSession()
  }
  const token = current?.token
  current = null
  if (!token) return
  try {
    await api.POST("/api/v1/auth/logout", { headers: { Authorization: `Bearer ${token}` } })
  } catch {
    // Unreachable: the session still ends here, and at the gateway after its idle time.
  }
}

const auth: Middleware = {
  async onRequest({ request }) {
    if (SELF_AUTHENTICATED.test(new URL(request.url).pathname) || request.headers.has("Authorization")) return request
    if (current?.refreshToken && current.expiresAt !== null && current.expiresAt - Date.now() < REFRESH_EARLY_MS) {
      await refreshSession()
    }
    if (current) request.headers.set("Authorization", `Bearer ${current.token}`)
    return request
  },
  async onResponse({ request, response }) {
    // A rejected session (ended, expired, or the user was deactivated): sign out, saying why.
    if (response.status === 401 && request.headers.has("Authorization") && !SELF_AUTHENTICATED.test(new URL(request.url).pathname)) {
      let reason: string | undefined
      try {
        const detail = ((await response.clone().json()) as FastApiError).detail
        if (typeof detail === "string" && detail !== "Could not validate credentials") reason = detail
      } catch {
        // No readable reason.
      }
      sessionLost(reason)
    }
    return response
  },
}

const BASE_URL: string = import.meta.env.VITE_API_URL || deployedApiUrl(window.location.hostname)

/** The gateway's address: this site's own when the dashboard reaches it through /api. */
export function gatewayUrl(): string {
  return (BASE_URL || window.location.origin).replace(/\/$/, "")
}

export const api = createClient<paths>({
  // VITE_API_URL when set (development, tests); on a hosted deployment, its gateway
  // (./deployment.ts); otherwise this origin, whose /api the Docker image forwards.
  baseUrl: BASE_URL,
  // Resolved on each call so tests can stub fetch.
  fetch: (request) => globalThis.fetch(request),
})
api.use(auth)

type FastApiError = { detail?: string | Array<{ msg?: string; loc?: Array<string | number> }> }

/** A readable message from FastAPI's error body: a string, or a list of validation errors. */
export function errorMessage(error: unknown, status: number): string {
  const detail = (error as FastApiError | undefined)?.detail
  if (typeof detail === "string") return detail
  if (Array.isArray(detail) && detail[0]?.msg) {
    const field = detail[0].loc?.filter((part) => part !== "body" && part !== "query").join(".")
    const message = detail[0].msg.replace(/^Value error, /, "")
    return field ? `${field}: ${message}` : message
  }
  if (status === 0) return "Cannot reach the API gateway."
  return `Request failed (${status}).`
}

/** The response data, or an ApiError for an error status or a network failure. */
export async function unwrap<T>(
  request: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  let result: { data?: T; error?: unknown; response: Response }
  try {
    result = await request
  } catch {
    throw new ApiError(0, errorMessage(undefined, 0))
  }
  const { data, error, response } = result
  if (!response.ok || error !== undefined) {
    throw new ApiError(response.status, errorMessage(error, response.status))
  }
  return data as T
}
