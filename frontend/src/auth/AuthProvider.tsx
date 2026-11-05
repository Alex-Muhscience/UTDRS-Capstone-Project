import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react"

import { api, ApiError, endSession, onSessionRefreshed, setAuthSession, unwrap, type User } from "@/api/client"
import { useAuthConfig } from "@/api/queries"

import { AuthContext, type AuthStatus, type AuthValue, type Registration } from "./context"
import { clearSession, readSession, saveSession, UNAUTHORIZED_EVENT, type Session } from "./session"

const EXPIRED = "Your session has ended. Sign in again to continue."
const IDLE = "You were signed out after a period of inactivity."
const DEFAULT_IDLE_MINUTES = 60
// What counts as someone using the dashboard; background refreshes of data do not.
const ACTIVITY = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart", "scroll"] as const

function initialSession(): Session | null {
  const session = readSession()
  // Set before the first render so the first requests already carry the token.
  setAuthSession(session)
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

  // Forget the session here; `atGateway` also ends it there (unless the gateway already did).
  const signOut = useCallback(
    (reason: string | null, atGateway: boolean) => {
      if (atGateway) void endSession()
      else setAuthSession(null)
      clearSession()
      queryClient.clear()
      setSession(null)
      setNotice(reason)
    },
    [queryClient],
  )
  const logout = useCallback((reason?: string) => signOut(reason ?? null, true), [signOut])

  const begin = useCallback(
    (token: { access_token?: string | null; refresh_token?: string | null; user?: User | null }) => {
      if (!token.access_token) throw new ApiError(401, "Sign-in did not complete.")
      const next = saveSession(token.access_token, token.refresh_token ?? null)
      setAuthSession(next)
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

  const loginWithSso = useCallback(
    async (code: string, state: string) => {
      begin(await unwrap(api.POST("/api/v1/auth/sso/callback", { body: { code, state } })))
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

  // The gateway ended the session: sign out here, saying why when it said.
  useEffect(() => {
    const onUnauthorized = (event: Event) => {
      const reason = (event as CustomEvent<string | undefined>).detail
      signOut(reason ? `${reason.replace(/[.:]?\s*sign in again$/i, "")}. Sign in again to continue.` : EXPIRED, false)
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [signOut])

  // New tokens from a refresh.
  useEffect(() => onSessionRefreshed(setSession), [])

  // Without a refresh token the session cannot outlive its access token.
  useEffect(() => {
    if (!session?.expiresAt || session.refreshToken) return
    const timer = window.setTimeout(() => logout(EXPIRED), Math.max(0, session.expiresAt - Date.now()))
    return () => window.clearTimeout(timer)
  }, [session, logout])

  // Sign out after the organisation's idle time without anyone using the dashboard. Its
  // background refreshes would otherwise keep the session going for ever.
  const config = useAuthConfig()
  const idleMinutes = config.data?.session_idle_minutes ?? DEFAULT_IDLE_MINUTES
  const lastActive = useRef(0) // set when the session starts
  const signedIn = session !== null
  useEffect(() => {
    if (!signedIn) return
    lastActive.current = Date.now()
    const active = () => {
      lastActive.current = Date.now()
    }
    ACTIVITY.forEach((name) => window.addEventListener(name, active, { passive: true }))
    const check = window.setInterval(() => {
      if (Date.now() - lastActive.current >= idleMinutes * 60_000) logout(IDLE)
    }, 15_000)
    return () => {
      ACTIVITY.forEach((name) => window.removeEventListener(name, active))
      window.clearInterval(check)
    }
  }, [signedIn, idleMinutes, logout])

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
      loginWithSso,
      register,
      logout,
      retry: () => void me.refetch(),
    }),
    [status, me, notice, start, loginWithCode, loginWithSso, register, logout],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}
