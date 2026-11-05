import createClient, { type Middleware } from "openapi-fetch"

import { deployedApiUrl } from "./deployment"
import type { components, paths } from "./schema"

export type Schemas = components["schemas"]
export type OperatorAccount = Schemas["OperatorAccount"]
export type OrganisationSummary = Schemas["OrganisationSummary"]
export type OrganisationDetail = Schemas["OrganisationDetail"]

/** An error response from the gateway, or a network failure (status 0). */
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

/**
 * The operator's session: a short token for the platform API only, kept for this tab.
 * It is refreshed shortly before it expires while the session lasts; the gateway ends the
 * session when it has not been used for a while, or is too old.
 */
type Session = { token: string; expiresAt: number }
const KEY = "utdrs.operator"
export const SIGNED_OUT_EVENT = "utdrs-operator:signed-out"
const listeners = new Set<() => void>()

/** Be told when the session starts or ends. */
export function onSessionChange(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}
const REFRESH_EARLY_MS = 60_000

function read(): Session | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    return raw ? (JSON.parse(raw) as Session) : null
  } catch {
    return null
  }
}

let current: Session | null = read()
let refreshing: Promise<void> | null = null

export function hasSession(): boolean {
  return current !== null && current.expiresAt > Date.now()
}

export function startSession(token: string, expiresIn: number): void {
  current = { token, expiresAt: Date.now() + expiresIn * 1000 }
  try {
    sessionStorage.setItem(KEY, JSON.stringify(current))
  } catch {
    // It lasts until the page is reloaded.
  }
  listeners.forEach((listener) => listener())
}

export function forgetSession(reason?: string): void {
  const had = current !== null
  current = null
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // Nothing stored.
  }
  listeners.forEach((listener) => listener())
  if (had) window.dispatchEvent(new CustomEvent(SIGNED_OUT_EVENT, { detail: reason }))
}

const BASE_URL: string = import.meta.env.VITE_API_URL || deployedApiUrl(window.location.hostname)

export const api = createClient<paths>({ baseUrl: BASE_URL, fetch: (request) => globalThis.fetch(request) })

// Sign-in steps carry their own proof (a password or a step token), not the session's.
const SIGNING_IN = /\/platform\/auth\/(login|mfa|enrol)$/

async function refresh(): Promise<void> {
  const session = current
  if (!session) return
  refreshing ??= (async () => {
    try {
      const response = await globalThis.fetch(
        new Request(`${BASE_URL}/api/v1/platform/auth/refresh`, { method: "POST", headers: { Authorization: `Bearer ${session.token}` } }),
      )
      if (response.ok) {
        const body = (await response.json()) as { access_token: string; expires_in: number }
        if (current === session) startSession(body.access_token, body.expires_in)
      }
    } catch {
      // Unreachable: the next request tries again.
    } finally {
      refreshing = null
    }
  })()
  await refreshing
}

const auth: Middleware = {
  async onRequest({ request }) {
    if (SIGNING_IN.test(new URL(request.url).pathname)) return request
    if (current && current.expiresAt - Date.now() < REFRESH_EARLY_MS) await refresh()
    if (current) request.headers.set("Authorization", `Bearer ${current.token}`)
    return request
  },
  async onResponse({ request, response }) {
    if (response.status === 401 && request.headers.has("Authorization")) {
      let reason: string | undefined
      try {
        const detail = ((await response.clone().json()) as { detail?: unknown }).detail
        if (typeof detail === "string") reason = detail
      } catch {
        // No reason given.
      }
      forgetSession(reason)
    }
    return response
  },
}
api.use(auth)

export function errorMessage(error: unknown, status: number): string {
  const detail = (error as { detail?: unknown } | undefined)?.detail
  if (typeof detail === "string") return detail
  if (Array.isArray(detail) && typeof detail[0]?.msg === "string") return String(detail[0].msg).replace(/^Value error, /, "")
  if (status === 0) return "Cannot reach the API gateway."
  return `Request failed (${status}).`
}

/** The response data, or an ApiError. */
export async function unwrap<T>(request: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  let result: { data?: T; error?: unknown; response: Response }
  try {
    result = await request
  } catch {
    throw new ApiError(0, errorMessage(undefined, 0))
  }
  if (!result.response.ok || result.error !== undefined) throw new ApiError(result.response.status, errorMessage(result.error, result.response.status))
  return result.data as T
}
