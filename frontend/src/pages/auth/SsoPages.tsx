import { CircleAlert, LoaderCircle } from "lucide-react"
import { useEffect, useRef, useState, type FormEvent } from "react"
import { Link, useLocation } from "react-router"

import { useStartSso } from "@/api/queries"
import { useAuth } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"
import { leaveFor } from "@/lib/navigate"

import { AuthLayout } from "./AuthLayout"

/** Sign in with the organisation's identity provider: the email's domain says which. */
export function SsoSignIn({ onCancel }: { onCancel: () => void }) {
  const start = useStartSso()

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const email = String(new FormData(event.currentTarget).get("email") ?? "").trim()
    start.mutate(email, { onSuccess: ({ url }) => leaveFor(url) })
  }

  return (
    <form key="sso" onSubmit={onSubmit} className="space-y-4">
      {start.isError && (
        <p className="flex gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger" role="alert">
          <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          {start.error.message}
        </p>
      )}
      <Field label="Work email" hint="You continue at your organisation's sign-in page.">
        {(id, describedBy) => <Input id={id} name="email" type="email" autoComplete="email" required autoFocus aria-describedby={describedBy} />}
      </Field>
      <Button type="submit" variant="primary" className="w-full" loading={start.isPending || start.isSuccess}>
        Continue
      </Button>
      <Button className="w-full" onClick={onCancel}>
        Sign in with a password
      </Button>
    </form>
  )
}

/** Where the identity provider sends people back, with a code and the state of the sign-in. */
export function SsoCallbackPage() {
  const { search } = useLocation()
  const { loginWithSso } = useAuth()
  const query = new URLSearchParams(search)
  const code = query.get("code")
  const state = query.get("state")
  // The provider sent back an error, or nothing to sign in with.
  const refused = code && state ? null : (query.get("error_description") ?? query.get("error") ?? "The sign-in did not complete.")
  const [failed, setFailed] = useState<string | null>(null)
  const sent = useRef(false)

  useEffect(() => {
    // Once: a code works once, and React may run effects twice in development.
    if (!code || !state || sent.current) return
    sent.current = true
    // On success GuestOnly moves on to the dashboard.
    loginWithSso(code, state).catch((caught: unknown) => setFailed(caught instanceof Error ? caught.message : "The sign-in did not complete."))
  }, [code, state, loginWithSso])

  const error = refused ?? failed

  return (
    <AuthLayout
      title="Signing in"
      subtitle={
        <Link to="/login" className="font-medium text-accent hover:underline">
          Back to sign in
        </Link>
      }
    >
      {error ? (
        <p className="flex gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger" role="alert">
          <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          {error}
        </p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted" role="status">
          <LoaderCircle className="size-4 animate-spin" aria-hidden /> Signing you in…
        </p>
      )}
    </AuthLayout>
  )
}
