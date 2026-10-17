import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import { useChangePassword, useCurrentTenant, useRenameTenant, useUpdateProfile } from "@/api/queries"
import { useIsAdmin, useUser } from "@/auth/context"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { formatDateTime, humanize } from "@/lib/format"

function OrganisationCard() {
  const tenant = useCurrentTenant()
  const rename = useRenameTenant()
  const isAdmin = useIsAdmin()
  if (!tenant.data) return null

  return (
    <Card
      title="Organisation"
      description={isAdmin ? "Everyone in it sees the same alerts, events, assets and rules, and nothing of other organisations." : "Your organisation's data is kept apart from every other's."}
    >
      {isAdmin ? (
        <form
          className="flex flex-col gap-3 sm:flex-row sm:items-end"
          onSubmit={(event: FormEvent<HTMLFormElement>) => {
            event.preventDefault()
            const name = String(new FormData(event.currentTarget).get("organisation") ?? "").trim()
            rename.mutate(name, {
              onSuccess: (updated) => toast.success(`Renamed to ${updated.name}`),
              onError: (error) => toast.error(error.message),
            })
          }}
        >
          <Field label="Name" required className="flex-1">
            {(id) => <Input id={id} name="organisation" defaultValue={tenant.data.name} required maxLength={100} />}
          </Field>
          <Button type="submit" loading={rename.isPending}>
            Rename
          </Button>
        </form>
      ) : (
        <DescriptionList items={[["Name", tenant.data.name]]} />
      )}
    </Card>
  )
}

export function ProfilePage() {
  const user = useUser()
  const update = useUpdateProfile()
  const changePassword = useChangePassword()
  const [passwordError, setPasswordError] = useState<string | null>(null)

  function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const value = (name: string) => String(data.get(name) ?? "").trim()
    update.mutate(
      { firstName: value("firstName") || null, lastName: value("lastName") || null, email: value("email") },
      {
        onSuccess: () => toast.success("Profile saved"),
        onError: (error) => toast.error(error.message),
      },
    )
  }

  function savePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const data = new FormData(form)
    const next = String(data.get("new_password") ?? "")
    if (next !== String(data.get("confirm_password") ?? "")) {
      setPasswordError("The new passwords do not match.")
      return
    }
    setPasswordError(null)
    changePassword.mutate(
      { current_password: String(data.get("current_password") ?? ""), new_password: next },
      {
        onSuccess: () => {
          toast.success("Password changed")
          form.reset()
        },
        onError: (error) => setPasswordError(error.message),
      },
    )
  }

  return (
    <>
      <PageHeader title="Profile" description="Your account on this UTDRS deployment." />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Account">
          <DescriptionList
            items={[
              ["Username", user.username],
              ["Role", <Badge key="role" tone="accent">{humanize(user.role)}</Badge>],
              ["Member since", formatDateTime(user.createdAt)],
              ["Last sign-in", formatDateTime(user.lastLogin)],
            ]}
          />
        </Card>

        <OrganisationCard />

        <Card title="Personal details" description="Your role can only be changed by an administrator.">
          <form onSubmit={saveProfile} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Field label="First name">{(id) => <Input id={id} name="firstName" defaultValue={user.firstName ?? ""} autoComplete="given-name" />}</Field>
              <Field label="Last name">{(id) => <Input id={id} name="lastName" defaultValue={user.lastName ?? ""} autoComplete="family-name" />}</Field>
            </div>
            <Field label="Email" required>
              {(id) => <Input id={id} name="email" type="email" defaultValue={user.email} required autoComplete="email" />}
            </Field>
            <Button type="submit" variant="primary" loading={update.isPending}>
              Save
            </Button>
          </form>
        </Card>

        <Card title="Password">
          <form onSubmit={savePassword} className="space-y-4">
            <Field label="Current password" required>
              {(id) => <Input id={id} name="current_password" type="password" required autoComplete="current-password" />}
            </Field>
            <Field label="New password" required hint="At least 8 characters.">
              {(id, describedBy) => (
                <Input id={id} name="new_password" type="password" required minLength={8} autoComplete="new-password" aria-describedby={describedBy} />
              )}
            </Field>
            <Field label="Confirm new password" required error={passwordError}>
              {(id, describedBy) => (
                <Input id={id} name="confirm_password" type="password" required minLength={8} autoComplete="new-password" aria-describedby={describedBy} />
              )}
            </Field>
            <Button type="submit" variant="primary" loading={changePassword.isPending}>
              Change password
            </Button>
          </form>
        </Card>
      </div>
    </>
  )
}
