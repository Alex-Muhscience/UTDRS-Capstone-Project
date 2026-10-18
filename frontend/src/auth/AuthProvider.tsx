import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react"

import { api, ApiError, setAuthToken, unwrap, type User } from "@/api/client"

import { AuthContext, type AuthStatus, type AuthValue, type Registration } from "./context"
import { clearSession, readSession, saveSession, UNAUTHORIZED_EVENT, type Session } from "./session"

const EXPIRED = "Your session has ended. Sign in again to continue."

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

  const begin = useCallback(
    (token: { access_token?: string | null; user?: User | null }) => {
      if (!token.access_token) throw new ApiError(401, "Sign-in did not complete.")
      const next = saveSession(token.access_token)
      setAuthToken(next.token)
      queryClient.setQueryData(["me"], token.user)
      setNotice(null)
      setSession(next)
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
      if (token.mfa_required && token.mfa_token) return { mfaToken: token.mfa_token }
      begin(token)
      return null
    },
    [begin],
  )

  const loginWithCode = useCallback(
    async (mfaToken: string, code: string) => {
      begin(await unwrap(api.POST("/api/v1/auth/login/mfa", { body: { mfa_token: mfaToken, code } })))
    },
    [begin],
  )

  const register = useCallback(
    async ({ username, email, password, firstName, lastName, organisation }: Registration) => {
      await unwrap(
        api.POST("/api/v1/auth/register", {
          // The gateway decides the role (an analyst, or a new organisation's administrator), whatever is sent.
          body: {
            organisation: organisation || null,
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
      loginWithCode,
      register,
      logout,
      retry: () => void me.refetch(),
    }),
    [status, me, notice, start, loginWithCode, register, logout],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}
