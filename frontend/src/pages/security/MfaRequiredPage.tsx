import { useQueryClient } from "@tanstack/react-query"

import { useAuth } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Logo } from "@/components/layout/Logo"

import { MfaSetup } from "./MfaSetup"

/** Shown instead of the app when the organisation requires MFA and this account has none yet. */
export function MfaRequiredPage() {
  const { logout } = useAuth()
  const queryClient = useQueryClient()
  return (
    <div className="grid min-h-dvh place-items-center p-6">
      <div className="w-full max-w-xl space-y-5 rounded-xl border border-border bg-surface p-6 shadow-card">
        <Logo />
        <div>
          <h1 className="text-lg font-semibold">Set up multi-factor authentication</h1>
          <p className="mt-1 text-sm text-muted">Your organisation requires it. Once it is set up, you can carry on to UTDRS.</p>
        </div>
        <MfaSetup onDone={() => void queryClient.invalidateQueries({ queryKey: ["me"] })} />
        <Button size="sm" onClick={() => logout()}>
          Sign out
        </Button>
      </div>
    </div>
  )
}
