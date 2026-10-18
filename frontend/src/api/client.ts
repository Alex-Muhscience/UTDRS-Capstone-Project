import createClient, { type Middleware } from "openapi-fetch"

import { UNAUTHORIZED_EVENT } from "@/auth/session"

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

let currentToken: string | null = null

/** The bearer token sent with every request; set by the auth provider. */
export function setAuthToken(token: string | null): void {
  currentToken = token
}

const auth: Middleware = {
  onRequest({ request }) {
    if (currentToken) request.headers.set("Authorization", `Bearer ${currentToken}`)
    return request
  },
  onResponse({ request, response }) {
    // A rejected token (expired, or the user was deactivated) ends the session.
    if (response.status === 401 && request.headers.has("Authorization")) {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT))
    }
    return response
  },
}

export const api = createClient<paths>({
  baseUrl: import.meta.env.VITE_API_URL ?? "",
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
