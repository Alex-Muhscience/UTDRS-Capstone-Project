import { useState } from "react"
import { useNavigate, useParams } from "react-router"
import { toast } from "sonner"

import type { OrganisationDetail } from "@/api/client"
import {
  useAddOrganisationAdmin,
  useDeleteOrganisation,
  useOrganisation,
  useOrganisations,
  useSetOrganisationMsp,
  useSetOrganisationSuspended,
} from "@/api/queries"
import { useUser } from "@/auth/context"
import { BackLink } from "@/components/ui/BackLink"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatNumber, formatRelative, humanize } from "@/lib/format"

import { OneTimePassword, PlatformError } from "./PlatformPage"

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface px-4 py-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums">{value}</p>
    </div>
  )
}

function AddAdministratorDialog({ tenantId, open, onClose, onCreated }: { tenantId: string; open: boolean; onClose: () => void; onCreated: (username: string, password: string) => void }) {
  const add = useAddOrganisationAdmin(tenantId)
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add an administrator"
      description="For an organisation whose administrators have left or are locked out. The organisation sees this in its own audit log."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        add.mutate(
          { username: String(data.get("username") ?? "").trim(), email: String(data.get("email") ?? "").trim() },
          {
            onSuccess: (result) => {
              onClose()
              onCreated(result.administrator.username, result.temporary_password)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={add.isPending}>
            Add
          </Button>
        </>
      }
    >
      <div className="grid gap-4">
        <Field label="Username" required>
          {(id) => <Input id={id} name="username" required minLength={3} maxLength={50} autoComplete="off" />}
        </Field>
        <Field label="Email" required>
          {(id) => <Input id={id} name="email" type="email" required autoComplete="off" />}
        </Field>
      </div>
    </Dialog>
  )
}

function DeleteDialog({ tenantId, name, open, onClose }: { tenantId: string; name: string; open: boolean; onClose: () => void }) {
  const remove = useDeleteOrganisation(tenantId)
  const navigate = useNavigate()
  const [typed, setTyped] = useState("")
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Delete ${name}?`}
      description="Its events, alerts, cases, people, keys, connectors and audit log are deleted, here and in the core engine. This cannot be undone. The platform's audit log keeps a record that it was deleted."
      onSubmit={() =>
        remove.mutate(typed, {
          onSuccess: () => {
            toast.success(`${name} deleted`)
            onClose()
            void navigate("/platform")
          },
          onError: (error) => toast.error(error.message),
        })
      }
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={typed !== name} loading={remove.isPending}>
            Delete for good
          </Button>
        </>
      }
    >
      <Field label={`Type ${name} to confirm`}>
        {(id) => <Input id={id} value={typed} onChange={(event) => setTyped(event.target.value)} autoComplete="off" />}
      </Field>
    </Dialog>
  )
}

/** Whether the organisation is a managed service provider, or which one manages it. */
function ServiceProviderCard({ org }: { org: OrganisationDetail }) {
  const change = useSetOrganisationMsp(org.id)
  const organisations = useOrganisations()
  const providers = (organisations.data ?? []).filter((item) => item.msp && item.id !== org.id)
  const save = (body: { msp?: boolean; managed_by?: string }, done: string) =>
    change.mutate(body, { onSuccess: () => toast.success(done), onError: (error) => toast.error(error.message) })
  return (
    <Card
      title="Service provider"
      description="A managed service provider (MSP) looks after other organisations: its people work in them with the same role they have in the MSP."
    >
      {org.msp ? (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <Badge tone="accent">Service provider</Badge>
          <span className="flex-1 text-muted">It can add clients, and you can assign organisations to it.</span>
          <Button size="sm" loading={change.isPending} onClick={() => save({ msp: false }, `${org.name} is no longer a service provider`)}>
            Stop being a service provider
          </Button>
        </div>
      ) : (
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Managed by" className="min-w-56 flex-1">
            {(id) => (
              <Select
                id={id}
                value={org.managed_by ?? ""}
                disabled={change.isPending}
                placeholder="No one"
                options={providers.map((provider) => ({ value: provider.id, label: provider.name }))}
                onChange={(event) =>
                  save({ managed_by: event.target.value }, event.target.value ? `${org.name} is now managed by ${providers.find((p) => p.id === event.target.value)?.name ?? "it"}` : `${org.name} is no longer managed`)
                }
              />
            )}
          </Field>
          {!org.managed_by && (
            <Button loading={change.isPending} onClick={() => save({ msp: true }, `${org.name} is now a service provider`)}>
              Make it a service provider
            </Button>
          )}
        </div>
      )}
    </Card>
  )
}

export function OrganisationPage() {
  const { tenantId = "" } = useParams()
  const me = useUser()
  const organisation = useOrganisation(tenantId)
  const suspend = useSetOrganisationSuspended(tenantId)
  const [adding, setAdding] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [created, setCreated] = useState<{ username: string; password: string } | null>(null)

  const header = <BackLink to="/platform">Platform console</BackLink>
  if (organisation.isError)
    return (
      <div className="space-y-6">
        {header}
        <PlatformError error={organisation.error} onRetry={() => void organisation.refetch()} />
      </div>
    )
  if (organisation.isPending)
    return (
      <div className="space-y-6">
        {header}
        <SkeletonRows rows={4} columns={4} />
      </div>
    )

  const org = organisation.data
  const suspended = org.status === "suspended"
  const own = org.users.some((user) => user.username === me.username)
  const protectedOrg = org.default || own
  return (
    <div className="space-y-6">
      {header}
      <PageHeader
        eyebrow="Organisation"
        title={
          <span className="flex flex-wrap items-center gap-2">
            {org.name}
            <Badge tone={suspended ? "danger" : "success"}>{humanize(org.status)}</Badge>
          </span>
        }
        description={`Created ${formatDateTime(org.created_at)}${org.mfa_required ? " · requires multi-factor authentication" : ""}`}
        actions={
          <>
            <Button onClick={() => setAdding(true)}>Add an administrator</Button>
            {!(own && !suspended) && (
              <Button
                variant={suspended ? "primary" : undefined}
                loading={suspend.isPending}
                onClick={() =>
                  suspend.mutate(!suspended, {
                    onSuccess: () => toast.success(suspended ? `${org.name} reactivated` : `${org.name} suspended; everyone in it is signed out`),
                    onError: (error) => toast.error(error.message),
                  })
                }
              >
                {suspended ? "Reactivate" : "Suspend"}
              </Button>
            )}
            {!protectedOrg && (
              <Button variant="danger" onClick={() => setDeleting(true)}>
                Delete
              </Button>
            )}
          </>
        }
      />
      {suspended && (
        <p className="rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm">
          Suspended: no one in {org.name} can sign in, and its API keys and SCIM token are refused. Its data is kept until you reactivate or delete it.
        </p>
      )}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="People" value={formatNumber(org.people)} />
        <Stat label="Administrators" value={formatNumber(org.administrators)} />
        <Stat label="Events (7 days)" value={formatNumber(org.events_last_week)} />
        <Stat label="Open alerts" value={formatNumber(org.open_alerts)} />
        <Stat label="Connectors" value={formatNumber(org.connectors)} />
      </div>
      <ServiceProviderCard org={org} />
      <Card title="People" description="Their accounts are managed by the organisation's own administrators." bodyClassName="p-0">
        <Table label="People">
          <thead>
            <tr>
              <Th>Username</Th>
              <Th>Email</Th>
              <Th className="w-32">Role</Th>
              <Th className="w-36">Last sign-in</Th>
            </tr>
          </thead>
          <tbody>
            {org.users.map((user) => (
              <Tr key={user.id}>
                <Td>
                  <span className="font-medium">{user.username}</span>
                  {user.platform_admin && <Badge className="ml-2">Platform</Badge>}
                  {!user.active && <Badge className="ml-2">Deactivated</Badge>}
                  {user.mfa && <span className="ml-2 text-xs text-subtle">MFA</span>}
                </Td>
                <Td className="text-muted">{user.email ?? "—"}</Td>
                <Td>{user.role === "viewer" ? "Read-only" : user.role === "custom" ? "Custom role" : humanize(user.role)}</Td>
                <Td className="text-muted" title={formatDateTime(user.last_sign_in)}>
                  {user.last_sign_in ? formatRelative(user.last_sign_in) : "Never"}
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <AddAdministratorDialog tenantId={tenantId} open={adding} onClose={() => setAdding(false)} onCreated={(username, password) => setCreated({ username, password })} />
      <DeleteDialog tenantId={tenantId} name={org.name} open={deleting} onClose={() => setDeleting(false)} />
      <OneTimePassword username={created?.username ?? ""} password={created?.password ?? null} onClose={() => setCreated(null)} />
    </div>
  )
}
