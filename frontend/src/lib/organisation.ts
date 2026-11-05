import { useSyncExternalStore } from "react"

/**
 * The client organisation a service provider's person is working in, or null for their own.
 * Sent with every request (X-UTDRS-Organisation); kept for the tab, like the session.
 */

export const ORGANISATION_HEADER = "X-UTDRS-Organisation"
/** Fired when the gateway refuses the organisation (no longer managed, suspended, ...). */
export const ORGANISATION_REFUSED_EVENT = "utdrs:organisation-refused"
const KEY = "utdrs.organisation"

function read(): string | null {
  try {
    return sessionStorage.getItem(KEY)
  } catch {
    return null
  }
}

let active: string | null = read()
const listeners = new Set<() => void>()

export function activeOrganisation(): string | null {
  return active
}

export function setActiveOrganisation(id: string | null): void {
  if (active === id) return
  active = id
  try {
    if (id) sessionStorage.setItem(KEY, id)
    else sessionStorage.removeItem(KEY)
  } catch {
    // Storage unavailable: it lasts until the page is reloaded.
  }
  listeners.forEach((listener) => listener())
}

export function useActiveOrganisation(): string | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    activeOrganisation,
  )
}
