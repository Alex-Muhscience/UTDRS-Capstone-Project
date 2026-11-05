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
  /** Finish signing in with single sign-on: the code and state the identity provider sent back. */
  loginWithSso: (code: string, state: string) => Promise<void>
  /** Sign in with a passkey this device has for UTDRS. */
  loginWithPasskey: () => Promise<void>
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

/** Whether someone may do this (`<area>:read` or `<area>:write`): by their custom role's permissions, or their built-in role. */
export function can(user: User | null | undefined, permission: string): boolean {
  if (!user) return false
  if (user.permissions) return user.permissions.includes(permission)
  if (user.role === "viewer") return permission.endsWith(":read")
  return true
}

/** A role's name for people: built-in roles by name, custom ones by theirs. */
export function roleLabel(user: Pick<User, "role" | "custom_role_name">): string {
  if (user.role === "custom") return user.custom_role_name ?? "Custom role"
  return { admin: "Administrator", analyst: "Analyst", viewer: "Read-only" }[user.role] ?? user.role
}

export function useCan(permission: string): boolean {
  return can(useAuth().user, permission)
}

/** Whether the signed-in user runs the platform (the console across organisations). */
export function useIsPlatformAdmin(): boolean {
  const { user } = useAuth()
  return Boolean(user?.platform_admin)
}

/** Whether the signed-in user can only look (the read-only role). */
export function useIsReadOnly(): boolean {
  const { user } = useAuth()
  return user?.role === "viewer"
}

/** Whether the signed-in user is an administrator (manages users, rules and simulations). */
export function useIsAdmin(): boolean {
  const { user } = useAuth()
  return user?.role === "admin"
}
