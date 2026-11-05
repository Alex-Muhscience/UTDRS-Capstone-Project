import { useSyncExternalStore } from "react"

import { hasSession, onSessionChange } from "@/api/client"

/** Whether an operator is signed in (in this tab). */
export function useSignedIn(): boolean {
  return useSyncExternalStore(onSessionChange, hasSession)
}
