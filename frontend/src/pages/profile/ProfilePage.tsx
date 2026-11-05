import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import { useChangePassword, useCurrentTenant, useReleaseFromMsp, useRenameTenant, useRequireMfa, useUpdateProfile } from "@/api/queries"
import { roleLabel, useIsAdmin, useUser } from "@/auth/context"
import { Badge } from "@/components/ui/Badge"
import { Button, ButtonLink } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { formatDateTime } from "@/lib/format"
import { useActiveOrganisation } from "@/lib/organisation"

import { PasskeysCard } from "@/pages/security/PasskeysCard"
import { SecurityCard } from "@/pages/security/SecurityCard"

import { NotificationsCard } from "./NotificationsCard"
import { SessionsCard } from "./SessionsCard"
import { ScimCard } from "./ScimCard"
import { SsoCard } from "./SsoCard"

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
      <RequireMfa required={tenant.data.require_mfa} isAdmin={isAdmin} />
      {tenant.data.managed_by_name && <ServiceProvider name={tenant.data.managed_by_name} isAdmin={isAdmin} />}
    </Card>
  )
}

/** The service provider that manages this organisation, and (for its own administrators) ending that. */
function ServiceProvider({ name, isAdmin }: { name: string; isAdmin: boolean }) {
  const release = useReleaseFromMsp()
  const acting = useActiveOrganisation() !== null
  const [confirming, setConfirming] = useState(false)
  return (
    <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-4 text-sm">
      <p className="min-w-0 flex-1">
        Managed by <strong>{name}</strong>: its people can work in this organisation, and what they do is in its audit log.
      </p>
      {isAdmin && !acting && (
        <Button size="sm" variant="danger" onClick={() => setConfirming(true)}>
          End their access
        </Button>
      )}
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={`End ${name}'s access?`}
        description="Its people can no longer see or change anything here. Only the platform's operator can give it back."
        footer={
          <>
            <Button onClick={() => setConfirming(false)}>Cancel</Button>
            <Button
              variant="danger"
              loading={release.isPending}
              onClick={() =>
                release.mutate(undefined, {
                  onSuccess: () => {
                    setConfirming(false)
                    toast.success(`${name} no longer has access`)
                  },
                  onError: (error) => toast.error(error.message),
                })
              }
            >
              End access
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">This is recorded in your audit log and theirs.</p>
      </Dialog>
    </div>
  )
}

function RequireMfa({ required, isAdmin }: { required: boolean; isAdmin: boolean }) {
  const update = useRequireMfa()
  return (
    <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4 text-sm">
      <span>
        <span className="block font-medium">Multi-factor authentication for everyone</span>
        <span className="block text-xs text-muted">
          {required ? "Required: people without it set it up when they next sign in." : "Not required: each person chooses."}
        </span>
      </span>
      {isAdmin && (
        <Button
          size="sm"
          loading={update.isPending}
          onClick={() =>
            update.mutate(!required, {
              onSuccess: () => toast.success(required ? "No longer required" : "Now required for everyone"),
              onError: (error) => toast.error(error.message),
            })
          }
        >
          {required ? "Stop requiring" : "Require"}
        </Button>
      )}
    </div>
  )
}

export function ProfilePage() {
  const user = useUser()
  const isAdmin = useIsAdmin()
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
        onSuccess: (saved) =>
          toast.success(
            saved.email !== user.email && !saved.email_verified ? "Profile saved. Confirm your new email address with the link we sent." : "Profile saved",
          ),
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
          toast.success("Password changed. You were signed out everywhere else.")
          form.reset()
        },
        onError: (error) => setPasswordError(error.message),
      },
    )
  }

  return (
    <>
      <PageHeader
        title="Profile"
        description="Your account on this UTDRS deployment."
        actions={
          <ButtonLink to="/get-started" size="sm">
            Setup checklist
          </ButtonLink>
        }
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Account">
          <DescriptionList
            items={[
              ["Username", user.username],
              [
                "Email",
                <span key="email" className="flex flex-wrap items-center gap-2">
                  {user.email}
                  {user.email_verified ? <Badge tone="success">Confirmed</Badge> : <Badge tone="warning">Not confirmed</Badge>}
                </span>,
              ],
              ["Role", <Badge key="role" tone="accent">{roleLabel(user)}</Badge>],
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

        <SecurityCard />

        <PasskeysCard />

        <SessionsCard />

        {isAdmin && <SsoCard />}

        {isAdmin && <ScimCard />}

        <NotificationsCard />
      </div>
    </>
  )
}
