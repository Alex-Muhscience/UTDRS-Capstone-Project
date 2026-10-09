import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react"

import { api, ApiError, setAuthToken, unwrap } from "@/api/client"

import { AuthContext, type AuthStatus, type AuthValue, type Registration } from "./context"
import { clearSession, readSession, saveSession, UNAUTHORIZED_EVENT, type Session } from "./session"

const EXPIRED = "Your session has expired. Sign in again to continue."

function initialSession(): Session | null {
  const session = readSession()
  // Set before the first render so the first requests already carry the token.
  setAuthToken(session?.token ?? null)
  return session
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [session, setSession] = useState<Session | null>(initialSession)
  const [notice, setNotice] = useState<string | null>(null)

  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => unwrap(api.GET("/api/v1/auth/me")),
    enabled: session !== null,
    staleTime: Infinity,
    retry: (count, error) => !(error instanceof ApiError && error.status === 401) && count < 2,
  })

  const logout = useCallback(
    (reason?: string) => {
      clearSession()
      setAuthToken(null)
      queryClient.clear()
      setSession(null)
      setNotice(reason ?? null)
    },
    [queryClient],
  )

  const start = useCallback(
    async (username: string, password: string) => {
      const token = await unwrap(
        api.POST("/api/v1/auth/login", {
          body: { username, password, scope: "" },
          bodySerializer: (body) => new URLSearchParams(body as Record<string, string>),
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
        }),
      )
      const next = saveSession(token.access_token)
      setAuthToken(next.token)
      queryClient.setQueryData(["me"], token.user)
      setNotice(null)
      setSession(next)
    },
    [queryClient],
  )

  const register = useCallback(
    async ({ username, email, password, firstName, lastName }: Registration) => {
      await unwrap(
        api.POST("/api/v1/auth/register", {
          // The gateway always registers new users as active analysts, whatever is sent.
          body: {
            username,
            email,
            password,
            firstName: firstName || null,
            lastName: lastName || null,
            role: "analyst",
            active: true,
          },
        }),
      )
      await start(username, password)
    },
    [start],
  )

  // The gateway rejected the token: sign out.
  useEffect(() => {
    const onUnauthorized = () => logout(EXPIRED)
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [logout])

  // Sign out when the token expires, rather than on the next failed request.
  useEffect(() => {
    if (!session?.expiresAt) return
    const timer = window.setTimeout(() => logout(EXPIRED), Math.max(0, session.expiresAt - Date.now()))
    return () => window.clearTimeout(timer)
  }, [session, logout])

  let status: AuthStatus
  if (!session) status = "signed-out"
  else if (me.data) status = "signed-in"
  else if (me.isError) status = me.error instanceof ApiError && me.error.status === 401 ? "signed-out" : "unavailable"
  else status = "loading"

  const value = useMemo<AuthValue>(
    () => ({
      status,
      user: status === "signed-in" ? (me.data ?? null) : null,
      notice,
      login: start,
      register,
      logout,
      retry: () => void me.refetch(),
    }),
    [status, me, notice, start, register, logout],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}
