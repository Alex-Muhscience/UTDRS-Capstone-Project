import { CircleAlert, Info, KeyRound } from "lucide-react"
import { useState, type FormEvent } from "react"
import { Link } from "react-router"

import { useAuthConfig, useResendVerification } from "@/api/queries"
import { useAuth } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"

import { passkeyErrorMessage, passkeysSupported } from "@/lib/webauthn"

import { AuthLayout } from "./AuthLayout"
import { SsoSignIn } from "./SsoPages"

export function LoginPage() {
  const { login, loginWithCode, loginWithPasskey, notice } = useAuth()
  const config = useAuthConfig()
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  // Set when the password was right and the account needs a second factor.
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  // Set when the account must confirm its email address before signing in.
  const [unconfirmed, setUnconfirmed] = useState<string | null>(null)
  const resend = useResendVerification()
  const [usingSso, setUsingSso] = useState(false)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setError(null)
    setPending(true)
    try {
      // On success GuestOnly takes the user on to where they were going.
      if (mfaToken) {
        await loginWithCode(mfaToken, String(form.get("code")).trim())
        return
      }
      setUnconfirmed(null)
      const next = await login(String(form.get("username")), String(form.get("password")))
      if (next) {
        setMfaToken(next.mfaToken)
        setPending(false)
      }
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "Sign-in failed."
      // The time for the code ran out: start again from the password.
      if (mfaToken && message.startsWith("Sign in again")) setMfaToken(null)
      if (message.startsWith("Confirm your email address")) setUnconfirmed(String(form.get("username")))
      // The organisation signs in only with SSO: take them there.
      if (message.includes("single sign-on")) setUsingSso(true)
      setError(message)
      setPending(false)
    }
  }

  return (
    <AuthLayout
      title="Sign in"
      subtitle={
        config.data?.allow_registration === false ? (
          "Accounts are created by an administrator."
        ) : (
          <>
            New here?{" "}
            <Link to="/register" className="font-medium text-accent hover:underline">
              Create an analyst account
            </Link>
          </>
        )
      }
    >
      {notice && !error && (
        <p className="mb-5 flex gap-2 rounded-lg border border-border bg-surface-2 p-3 text-sm text-muted" role="status">
          <Info className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
          {notice}
        </p>
      )}
      {error && (
        <p className="mb-5 flex gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger" role="alert">
          <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            {error}
            {unconfirmed && (
              <>
                {" "}
                {resend.isSuccess ? (
                  "A new link is on its way."
                ) : (
                  <button type="button" className="font-medium underline" disabled={resend.isPending} onClick={() => resend.mutate(unconfirmed)}>
                    Send the link again
                  </button>
                )}
              </>
            )}
          </span>
        </p>
      )}
      {usingSso ? (
        <SsoSignIn onCancel={() => setUsingSso(false)} />
      ) : mfaToken ? (
        // Keyed apart from the password form, so no field carries over (the username into the code box).
        <form key="code" onSubmit={onSubmit} className="space-y-4">
          <Field label="Authentication code" hint="From your authenticator app, or one of your recovery codes.">
            {(id, describedBy) => (
              <Input id={id} name="code" inputMode="numeric" autoComplete="one-time-code" required autoFocus maxLength={20} aria-describedby={describedBy} />
            )}
          </Field>
          <Button type="submit" variant="primary" className="w-full" loading={pending}>
            Verify
          </Button>
          <Button
            className="w-full"
            onClick={() => {
              setMfaToken(null)
              setError(null)
            }}
          >
            Use a different account
          </Button>
        </form>
      ) : (
      <form key="password" onSubmit={onSubmit} className="space-y-4">
        <Field label="Username">
          {(id) => <Input id={id} name="username" autoComplete="username" required autoFocus />}
        </Field>
        <Field label="Password">
          {(id) => <Input id={id} name="password" type="password" autoComplete="current-password" required />}
        </Field>
        {config.data?.password_reset && (
          <p className="-mt-2 text-right text-sm">
            <Link to="/forgot-password" className="text-accent hover:underline">
              Forgot your password?
            </Link>
          </p>
        )}
        <Button type="submit" variant="primary" className="w-full" loading={pending}>
          Sign in
        </Button>
        {passkeysSupported() && (
          <Button
            className="w-full"
            loading={pending}
            onClick={() => {
              setError(null)
              setPending(true)
              loginWithPasskey().catch((caught: unknown) => {
                setError(passkeyErrorMessage(caught))
                setPending(false)
              })
            }}
          >
            <KeyRound className="size-4" aria-hidden /> Sign in with a passkey
          </Button>
        )}
        {config.data?.sso_available && (
          <Button className="w-full" onClick={() => setUsingSso(true)}>
            Sign in with SSO
          </Button>
        )}
      </form>
      )}
    </AuthLayout>
  )
}
