import { useQueryClient } from "@tanstack/react-query"
import { useCallback, useEffect } from "react"
import { useNavigate } from "react-router"
import { toast } from "sonner"

import { ORGANISATION_REFUSED_EVENT, setActiveOrganisation } from "./organisation"

/** What is kept when switching organisation: who you are and your provider's view. */
const KEPT = new Set(["me", "msp", "auth"])

/** Work in another organisation (a client), or back in your own (null): every page then shows that one's data. */
export function useSwitchOrganisation() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  return useCallback(
    (id: string | null, to = "/") => {
      setActiveOrganisation(id)
      void queryClient.resetQueries({ predicate: (query) => !KEPT.has(String(query.queryKey[0])) })
      void navigate(to)
    },
    [queryClient, navigate],
  )
}

/** Back to your own organisation when the gateway refuses the client (no longer managed, suspended, ...). */
export function useOrganisationRefused() {
  const switchTo = useSwitchOrganisation()
  useEffect(() => {
    const refused = (event: Event) => {
      toast.error((event as CustomEvent<string | undefined>).detail ?? "You can no longer work in that organisation")
      switchTo(null)
    }
    window.addEventListener(ORGANISATION_REFUSED_EVENT, refused)
    return () => window.removeEventListener(ORGANISATION_REFUSED_EVENT, refused)
  }, [switchTo])
}
