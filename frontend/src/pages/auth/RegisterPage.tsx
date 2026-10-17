import { CircleAlert } from "lucide-react"
import { useState, type FormEvent } from "react"
import { Link } from "react-router"

import { useAuthConfig } from "@/api/queries"
import { useAuth } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"

import { AuthLayout } from "./AuthLayout"

export function RegisterPage() {
  const { register } = useAuth()
  const config = useAuthConfig()
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const value = (name: string) => String(form.get(name) ?? "").trim()
    setError(null)
    setPending(true)
    try {
      await register({
        username: value("username"),
        email: value("email"),
        password: String(form.get("password") ?? ""),
        firstName: value("firstName"),
        lastName: value("lastName"),
        organisation: value("organisation"),
      })
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Registration failed.")
      setPending(false)
    }
  }

  if (config.data?.allow_registration === false) {
    return (
      <AuthLayout title="Registration is closed" subtitle="Accounts on this deployment are created by an administrator.">
        <Link to="/login" className="text-sm font-medium text-accent hover:underline">
          Back to sign in
        </Link>
      </AuthLayout>
    )
  }

  const creatingOrganisation = config.data?.registration_mode === "organisation"
  return (
    <AuthLayout
      title={creatingOrganisation ? "Create your organisation" : "Create an account"}
      subtitle={
        <>
          {creatingOrganisation
            ? "You will be its administrator, and can add your team after. "
            : "New accounts are analysts. "}
          Already registered?{" "}
          <Link to="/login" className="font-medium text-accent hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      {error && (
        <p className="mb-5 flex gap-2 rounded-lg border border-danger/30 bg-danger/10 p-3 text-sm text-danger" role="alert">
          <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          {error}
        </p>
      )}
      <form onSubmit={onSubmit} className="space-y-4">
        {creatingOrganisation && (
          <Field label="Organisation" required>
            {(id) => <Input id={id} name="organisation" autoComplete="organization" required maxLength={100} />}
          </Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="First name">{(id) => <Input id={id} name="firstName" autoComplete="given-name" />}</Field>
          <Field label="Last name">{(id) => <Input id={id} name="lastName" autoComplete="family-name" />}</Field>
        </div>
        <Field label="Username" required>
          {(id) => <Input id={id} name="username" autoComplete="username" required minLength={3} />}
        </Field>
        <Field label="Email" required>
          {(id) => <Input id={id} name="email" type="email" autoComplete="email" required />}
        </Field>
        <Field label="Password" required hint="At least 8 characters.">
          {(id, describedBy) => (
            <Input
              id={id}
              name="password"
              type="password"
              autoComplete="new-password"
              required
              minLength={8}
              aria-describedby={describedBy}
            />
          )}
        </Field>
        <Button type="submit" variant="primary" className="w-full" loading={pending}>
          Create account
        </Button>
      </form>
    </AuthLayout>
  )
}
