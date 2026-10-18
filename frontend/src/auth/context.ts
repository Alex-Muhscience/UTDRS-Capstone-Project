import { createContext, useContext } from "react"

import type { User } from "@/api/client"

export type AuthStatus = "loading" | "signed-in" | "signed-out" | "unavailable"

export type Registration = {
  username: string
  email: string
  password: string
  firstName?: string
  lastName?: string
  // The organisation to create, when registering creates organisations.
  organisation?: string
}

export type AuthValue = {
  status: AuthStatus
  user: User | null
  /** Why the user was signed out, shown on the sign-in page. */
  notice: string | null
  /** Sign in with a password. With MFA on, resolves to the token for the second step instead. */
  login: (username: string, password: string) => Promise<{ mfaToken: string } | null>
  /** Finish signing in with a code from the authenticator app, or a recovery code. */
  loginWithCode: (mfaToken: string, code: string) => Promise<void>
  register: (registration: Registration) => Promise<void>
  logout: (notice?: string) => void
  retry: () => void
}

export const AuthContext = createContext<AuthValue | null>(null)

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>")
  return value
}

/** The signed-in user; only for components rendered behind <RequireAuth>. */
export function useUser(): User {
  const { user } = useAuth()
  if (!user) throw new Error("useUser needs a signed-in user")
  return user
}

/** Whether the signed-in user is an administrator (manages users, rules and simulations). */
export function useIsAdmin(): boolean {
  const { user } = useAuth()
  return user?.role === "admin"
}
