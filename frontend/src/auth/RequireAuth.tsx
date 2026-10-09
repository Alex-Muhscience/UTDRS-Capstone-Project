import { Navigate, Outlet, useLocation, type Location } from "react-router"

import { Button } from "@/components/ui/Button"
import { FullPageSpinner } from "@/components/ui/Spinner"

import { useAuth } from "./context"

/** Renders child routes for a signed-in user; otherwise sends them to sign in. */
export function RequireAuth() {
  const { status, retry, logout } = useAuth()
  const location = useLocation()

  if (status === "loading") return <FullPageSpinner label="Loading your session" />
  if (status === "unavailable") {
    return (
      <div className="grid min-h-dvh place-items-center p-6">
        <div className="max-w-sm text-center">
          <h1 className="text-lg font-semibold">The API gateway is not responding</h1>
          <p className="mt-2 text-sm text-muted">
            Check that the gateway is running and reachable from this page, then try again.
          </p>
          <div className="mt-5 flex justify-center gap-2">
            <Button variant="primary" onClick={retry}>
              Try again
            </Button>
            <Button onClick={() => logout()}>Sign out</Button>
          </div>
        </div>
      </div>
    )
  }
  if (status === "signed-out") return <Navigate to="/login" replace state={{ from: location }} />
  return <Outlet />
}

/**
 * Sign-in and registration pages. Once signed in, the user goes to the page they
 * were sent away from (see RequireAuth), or to the overview.
 */
export function GuestOnly() {
  const { status } = useAuth()
  const location = useLocation()
  if (status === "signed-in") {
    const from = (location.state as { from?: Location } | null)?.from
    return <Navigate to={from ? `${from.pathname}${from.search}` : "/"} replace />
  }
  return <Outlet />
}
