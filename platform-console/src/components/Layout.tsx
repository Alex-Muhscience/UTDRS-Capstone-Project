import { useQueryClient } from "@tanstack/react-query"
import { Building2, LogOut, ScrollText, ShieldCheck, Users } from "lucide-react"
import { useEffect } from "react"
import { Navigate, NavLink, Outlet, useNavigate } from "react-router"
import { toast } from "sonner"

import { api, forgetSession, SIGNED_OUT_EVENT } from "@/api/client"
import { useMe } from "@/api/queries"
import { FullPageSpinner } from "@/components/ui/Spinner"
import { ErrorState } from "@/components/ui/States"
import { cx } from "@/lib/cx"
import { useSignedIn } from "@/lib/session"
import { ChangePasswordPage } from "@/pages/ChangePasswordPage"

const NAVIGATION = [
  { to: "/", label: "Organisations", icon: Building2, end: true },
  { to: "/operators", label: "Operators", icon: Users },
  { to: "/audit-log", label: "Audit log", icon: ScrollText },
]

/** Back to the sign-in page, saying why, whenever the session ends. */
function useSignedOutRedirect() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  useEffect(() => {
    const signedOut = (event: Event) => {
      const reason = (event as CustomEvent<string | undefined>).detail
      queryClient.clear()
      if (reason) toast.error(reason)
      void navigate("/sign-in", { replace: true })
    }
    window.addEventListener(SIGNED_OUT_EVENT, signedOut)
    return () => window.removeEventListener(SIGNED_OUT_EVENT, signedOut)
  }, [navigate, queryClient])
}

export function Layout() {
  const signedIn = useSignedIn()
  useSignedOutRedirect()
  const me = useMe(signedIn)
  if (!signedIn) return <Navigate to="/sign-in" replace />
  if (me.isPending) return <FullPageSpinner label="Loading" />
  if (me.isError) return <ErrorState error={me.error} onRetry={() => void me.refetch()} />
  if (me.data.must_change_password) return <ChangePasswordPage forced />

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
          <span className="flex items-center gap-2 text-sm font-semibold">
            <ShieldCheck className="size-5 text-accent" aria-hidden />
            UTDRS operator console
          </span>
          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {NAVIGATION.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  cx("flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium", isActive ? "bg-accent/12 text-fg" : "text-muted hover:bg-surface-2 hover:text-fg")
                }
              >
                <Icon className="size-4" aria-hidden />
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="text-muted">{me.data.username}</span>
            <button
              type="button"
              className="flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-muted hover:bg-surface-2 hover:text-fg"
              onClick={() => {
                void api.POST("/api/v1/platform/auth/logout").finally(() => forgetSession())
              }}
            >
              <LogOut className="size-4" aria-hidden /> Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:py-8">
        <Outlet />
      </main>
    </div>
  )
}
