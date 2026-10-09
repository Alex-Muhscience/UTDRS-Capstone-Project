/**
 * The signed-in session: the gateway's JWT and when it expires.
 *
 * Kept in sessionStorage, so it survives a reload but not closing the tab, and is
 * never shared between tabs. The gateway issues bearer tokens (no cookies), so the
 * token has to be readable by the app; the Content-Security-Policy in nginx.conf
 * limits what scripts could read it.
 */
const KEY = "utdrs-session"

export type Session = { token: string; expiresAt: number | null }

/** Expiry (ms since epoch) from a JWT's `exp` claim, or null if it has none. */
export function tokenExpiry(token: string): number | null {
  const payload = token.split(".")[1]
  if (!payload) return null
  try {
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
    const exp = (JSON.parse(json) as { exp?: unknown }).exp
    return typeof exp === "number" ? exp * 1000 : null
  } catch {
    return null
  }
}

export function isExpired(session: Session, now = Date.now()): boolean {
  return session.expiresAt !== null && session.expiresAt <= now
}

export function readSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    if (!raw) return null
    const session = JSON.parse(raw) as Session
    if (typeof session.token !== "string" || isExpired(session)) {
      sessionStorage.removeItem(KEY)
      return null
    }
    return session
  } catch {
    return null
  }
}

export function saveSession(token: string): Session {
  const session = { token, expiresAt: tokenExpiry(token) }
  try {
    sessionStorage.setItem(KEY, JSON.stringify(session))
  } catch {
    // Storage can be unavailable (private mode, blocked site data): the session then lasts until reload.
  }
  return session
}

export function clearSession(): void {
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // Nothing stored.
  }
}

/** Dispatched when the gateway rejects the token, so the app can sign out. */
export const UNAUTHORIZED_EVENT = "utdrs:unauthorized"
