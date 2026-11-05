import { CircleAlert, CircleCheck, LoaderCircle, MailCheck } from "lucide-react"
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react"
import { Link, useLocation } from "react-router"

import { useAuthConfig, useChooseNewPassword, useForgotPassword, useVerifyEmail } from "@/api/queries"
import { useAuth } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"

import { AuthLayout } from "./AuthLayout"

function Message({ tone, children }: { tone: "error" | "success" | "info"; children: ReactNode }) {
  const styles = {
    error: "border-danger/30 bg-danger/10 text-danger",
    success: "border-success/30 bg-success/10 text-fg",
    info: "border-border bg-surface-2 text-muted",
  }[tone]
  const Icon = tone === "error" ? CircleAlert : tone === "success" ? CircleCheck : MailCheck
  return (
    <p className={`mb-5 flex gap-2 rounded-lg border p-3 text-sm ${styles}`} role={tone === "error" ? "alert" : "status"}>
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  )
}

const BACK_TO_SIGN_IN = (
  <Link to="/login" className="font-medium text-accent hover:underline">
    Back to sign in
  </Link>
)

/**
 * The token from an emailed link, read once. It is in the fragment (#token=…), which
 * browsers never send to servers, and is cleared from the address bar once read.
 */
function useLinkToken(): string {
  const { hash, pathname } = useLocation()
  const [token] = useState(() => new URLSearchParams(hash.replace(/^#/, "")).get("token") ?? "")
  useEffect(() => {
    if (window.location.hash) window.history.replaceState(null, "", pathname)
  }, [pathname])
  return token
}

export function ForgotPasswordPage() {
  const config = useAuthConfig()
  const forgot = useForgotPassword()

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    forgot.mutate(String(new FormData(event.currentTarget).get("login") ?? "").trim())
  }

  return (
    <AuthLayout title="Forgot your password?" subtitle={BACK_TO_SIGN_IN}>
      {config.data?.password_reset === false ? (
        <Message tone="info">This deployment cannot send email. Ask an administrator to reset your password.</Message>
      ) : forgot.isSuccess ? (
        <Message tone="success">{forgot.data.message}</Message>
      ) : (
        <>
          {forgot.isError && <Message tone="error">{forgot.error.message}</Message>}
          <form onSubmit={onSubmit} className="space-y-4">
            <Field label="Username or email address" hint="We email you a link to choose a new password.">
              {(id, describedBy) => <Input id={id} name="login" autoComplete="username" required autoFocus aria-describedby={describedBy} />}
            </Field>
            <Button type="submit" variant="primary" className="w-full" loading={forgot.isPending}>
              Email me a link
            </Button>
          </form>
        </>
      )}
    </AuthLayout>
  )
}

export function ResetPasswordPage() {
  const token = useLinkToken()
  const choose = useChooseNewPassword()
  const [mismatch, setMismatch] = useState(false)

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const next = String(form.get("new_password") ?? "")
    setMismatch(next !== String(form.get("confirm_password") ?? ""))
    if (next === String(form.get("confirm_password") ?? "")) choose.mutate({ token, new_password: next })
  }

  return (
    <AuthLayout title="Choose a new password" subtitle={BACK_TO_SIGN_IN}>
      {!token ? (
        <Message tone="error">
          This link is incomplete. Open the link from the email again, or <Link to="/forgot-password" className="underline">ask for a new one</Link>.
        </Message>
      ) : choose.isSuccess ? (
        <>
          <Message tone="success">{choose.data.message} You were signed out everywhere else.</Message>
          <Link to="/login" className="font-medium text-accent hover:underline">
            Sign in
          </Link>
        </>
      ) : (
        <>
          {choose.isError && (
            <Message tone="error">
              {choose.error.message}{" "}
              <Link to="/forgot-password" className="underline">
                Ask for a new link
              </Link>
            </Message>
          )}
          <form onSubmit={onSubmit} className="space-y-4">
            <Field label="New password" required hint="At least 8 characters.">
              {(id, describedBy) => (
                <Input id={id} name="new_password" type="password" required minLength={8} autoComplete="new-password" autoFocus aria-describedby={describedBy} />
              )}
            </Field>
            <Field label="Confirm new password" required error={mismatch ? "The passwords do not match." : null}>
              {(id, describedBy) => (
                <Input id={id} name="confirm_password" type="password" required minLength={8} autoComplete="new-password" aria-describedby={describedBy} />
              )}
            </Field>
            <Button type="submit" variant="primary" className="w-full" loading={choose.isPending}>
              Change password
            </Button>
          </form>
        </>
      )}
    </AuthLayout>
  )
}

export function VerifyEmailPage() {
  const token = useLinkToken()
  const verify = useVerifyEmail()
  const { status } = useAuth()
  const sent = useRef(false)

  useEffect(() => {
    // Once: the link works once, and React may run effects twice in development.
    if (!token || sent.current) return
    sent.current = true
    verify.mutate(token)
  }, [token, verify])

  const onward =
    status === "signed-in" ? (
      <Link to="/" className="font-medium text-accent hover:underline">
        Go to the dashboard
      </Link>
    ) : (
      BACK_TO_SIGN_IN
    )

  return (
    <AuthLayout title="Confirm your email address" subtitle={onward}>
      {!token ? (
        <Message tone="error">This link is incomplete. Open the link from the email again.</Message>
      ) : verify.isSuccess ? (
        <Message tone="success">{verify.data.message}</Message>
      ) : verify.isError ? (
        <Message tone="error">{verify.error.message}</Message>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted" role="status">
          <LoaderCircle className="size-4 animate-spin" aria-hidden /> Confirming…
        </p>
      )}
    </AuthLayout>
  )
}
