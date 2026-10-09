import { CircleAlert, Info } from "lucide-react"
import { useState, type FormEvent } from "react"
import { Link } from "react-router"

import { useAuth } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"

import { AuthLayout } from "./AuthLayout"

export function LoginPage() {
  const { login, notice } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setError(null)
    setPending(true)
    try {
      // On success GuestOnly takes the user on to where they were going.
      await login(String(form.get("username")), String(form.get("password")))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign-in failed.")
      setPending(false)
    }
  }

  return (
    <AuthLayout
      title="Sign in"
      subtitle={
        <>
          New here?{" "}
          <Link to="/register" className="font-medium text-accent hover:underline">
            Create an analyst account
          </Link>
        </>
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
          {error}
        </p>
      )}
      <form onSubmit={onSubmit} className="space-y-4">
        <Field label="Username">
          {(id) => <Input id={id} name="username" autoComplete="username" required autoFocus />}
        </Field>
        <Field label="Password">
          {(id) => <Input id={id} name="password" type="password" autoComplete="current-password" required />}
        </Field>
        <Button type="submit" variant="primary" className="w-full" loading={pending}>
          Sign in
        </Button>
      </form>
    </AuthLayout>
  )
}
