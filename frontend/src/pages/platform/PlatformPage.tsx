import { Check, Copy, Plus, ShieldAlert } from "lucide-react"
import { useState, type ReactNode } from "react"
import { Link, useNavigate } from "react-router"
import { toast } from "sonner"

import { ApiError, type AuditEntry } from "@/api/client"
import { useCreateOrganisation, useOrganisations, usePlatformAdmins, usePlatformAuditLog, useSetPlatformAdmin } from "@/api/queries"
import { useUser } from "@/auth/context"
import { Badge } from "@/components/ui/Badge"
import { Button, ButtonLink } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatNumber, formatRelative, humanize } from "@/lib/format"

/** The console refuses sessions signed in without a second factor; say what to do about it. */
export function PlatformError({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (error instanceof ApiError && error.status === 403) {
    return (
      <Card>
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          <div className="space-y-3 text-sm">
            <p className="font-medium">{error.message}</p>
            <p className="text-muted">
              The platform console reaches every organisation, so it asks for more than a password. Set up an authenticator app or a passkey on
              your profile, sign out, and sign in again with it.
            </p>
            <ButtonLink to="/profile" size="sm">
              Go to your profile
            </ButtonLink>
          </div>
        </div>
      </Card>
    )
  }
  return <ErrorState error={error} onRetry={onRetry} />
}

/** A password shown once, with a copy button. */
export function OneTimePassword({ username, password, onClose }: { username: string; password: string | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <Dialog
      open={password !== null}
      onClose={onClose}
      title="Temporary password"
      description={`Shown only this once. Give it to ${username} by a safe channel; they choose their own password and set up a second factor when they first sign in.`}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className="space-y-3">
        <p className="text-sm">
          Username: <span className="font-mono">{username}</span>
        </p>
        <code className="block break-all rounded-lg bg-surface-2 p-3 font-mono text-sm">{password}</code>
        <Button
          size="sm"
          onClick={() => {
            void navigator.clipboard?.writeText(password ?? "")
            setCopied(true)
          }}
        >
          {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />} {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </Dialog>
  )
}

function NewOrganisationDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (username: string, password: string, tenantId: string) => void }) {
  const create = useCreateOrganisation()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="New organisation"
      description="An organisation keeps its own data, people and settings. Its first administrator gets a temporary password to sign in with."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const field = (name: string) => String(data.get(name) ?? "").trim()
        create.mutate(
          { name: field("name"), admin_username: field("admin_username"), admin_email: field("admin_email") },
          {
            onSuccess: (result) => {
              onClose()
              onCreated(result.administrator.username, result.temporary_password, result.tenant.id)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Organisation name" required className="sm:col-span-2">
          {(id) => <Input id={id} name="name" required maxLength={100} placeholder="Acme Ltd" />}
        </Field>
        <Field label="Administrator's username" required>
          {(id) => <Input id={id} name="admin_username" required minLength={3} maxLength={50} autoComplete="off" />}
        </Field>
        <Field label="Administrator's email" required>
          {(id) => <Input id={id} name="admin_email" type="email" required autoComplete="off" />}
        </Field>
      </div>
    </Dialog>
  )
}

function Organisations() {
  const organisations = useOrganisations()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState<{ username: string; password: string; tenantId: string } | null>(null)

  if (organisations.isError) return <PlatformError error={organisations.error} onRetry={() => void organisations.refetch()} />
  return (
    <>
      <Card
        title="Organisations"
        description="Every organisation on this deployment. Open one to add an administrator, suspend it or delete it."
        actions={
          <Button size="sm" variant="primary" onClick={() => setCreating(true)}>
            <Plus className="size-4" aria-hidden /> New organisation
          </Button>
        }
        bodyClassName="p-0"
      >
        {organisations.isPending ? (
          <SkeletonRows rows={3} columns={6} />
        ) : !organisations.data?.length ? (
          <EmptyState title="No organisations yet" />
        ) : (
          <Table label="Organisations">
            <thead>
              <tr>
                <Th>Organisation</Th>
                <Th className="w-24">Status</Th>
                <Th className="w-20 text-right">People</Th>
                <Th className="w-28 text-right">Events (7 days)</Th>
                <Th className="w-24 text-right">Open alerts</Th>
                <Th className="w-36">Last sign-in</Th>
              </tr>
            </thead>
            <tbody>
              {organisations.data.map((organisation) => (
                <Tr key={organisation.id} onClick={() => void navigate(`/platform/organisations/${organisation.id}`)}>
                  <Td>
                    <Link to={`/platform/organisations/${organisation.id}`} className="font-medium hover:underline" onClick={(event) => event.stopPropagation()}>
                      {organisation.name}
                    </Link>
                    {organisation.default && <span className="ml-2 text-xs text-subtle">platform's own</span>}
                  </Td>
                  <Td>
                    <Badge tone={organisation.status === "active" ? "success" : "danger"}>{humanize(organisation.status)}</Badge>
                  </Td>
                  <Td className="text-right tabular-nums">{formatNumber(organisation.people)}</Td>
                  <Td className="text-right tabular-nums">{formatNumber(organisation.events_last_week)}</Td>
                  <Td className="text-right tabular-nums">{formatNumber(organisation.open_alerts)}</Td>
                  <Td className="text-muted" title={formatDateTime(organisation.last_sign_in)}>
                    {organisation.last_sign_in ? formatRelative(organisation.last_sign_in) : "Never"}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <NewOrganisationDialog open={creating} onClose={() => setCreating(false)} onCreated={(username, password, tenantId) => setCreated({ username, password, tenantId })} />
      <OneTimePassword
        username={created?.username ?? ""}
        password={created?.password ?? null}
        onClose={() => {
          const tenantId = created?.tenantId
          setCreated(null)
          if (tenantId) void navigate(`/platform/organisations/${tenantId}`)
        }}
      />
    </>
  )
}

function PlatformAdmins() {
  const me = useUser()
  const admins = usePlatformAdmins()
  const change = useSetPlatformAdmin()
  const [username, setUsername] = useState("")

  if (admins.isError) return null // the organisations card already explains
  const set = (name: string, value: boolean) =>
    change.mutate(
      { username: name, platform_admin: value },
      {
        onSuccess: () => {
          toast.success(value ? `${name} is now a platform administrator` : `${name} is no longer a platform administrator`)
          setUsername("")
        },
        onError: (error) => toast.error(error.message),
      },
    )
  return (
    <Card title="Platform administrators" description="People who can use this console. Each must sign in with a second factor to use it." bodyClassName="p-0">
      {admins.isPending ? (
        <SkeletonRows rows={2} columns={4} />
      ) : (
        <ul className="divide-y divide-border" aria-label="Platform administrators">
          {(admins.data ?? []).map((admin) => (
            <li key={admin.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
              <span className="font-medium">{admin.username}</span>
              <span className="text-muted">{admin.organisation ?? "—"}</span>
              {!admin.mfa && <Badge tone="warning">No second factor</Badge>}
              {!admin.active && <Badge>Deactivated</Badge>}
              {admin.username !== me.username && (
                <Button size="sm" variant="ghost" className="ml-auto" disabled={change.isPending} onClick={() => set(admin.username, false)}>
                  Remove
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <form
        className="flex flex-wrap items-end gap-2 border-t border-border px-5 py-4"
        onSubmit={(event) => {
          event.preventDefault()
          if (username.trim()) set(username.trim(), true)
        }}
      >
        <Field label="Make someone a platform administrator" className="min-w-56 flex-1">
          {(id) => <Input id={id} value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Their username" autoComplete="off" />}
        </Field>
        <Button type="submit" disabled={!username.trim()} loading={change.isPending}>
          Add
        </Button>
      </form>
    </Card>
  )
}

function actor(entry: AuditEntry): ReactNode {
  const name = typeof entry.actor.name === "string" ? entry.actor.name : null
  return name ?? humanize(String(entry.actor.type))
}

function PlatformAuditLog() {
  const log = usePlatformAuditLog()
  if (log.isError) return null
  const entries = (log.data ?? []) as unknown as AuditEntry[]
  return (
    <Card title="Platform audit log" description="Every action taken in this console, and sign-in attempts to accounts that do not exist." bodyClassName="p-0">
      {log.isPending ? (
        <SkeletonRows rows={3} columns={3} />
      ) : !entries.length ? (
        <p className="px-5 py-4 text-sm text-muted">Nothing recorded yet.</p>
      ) : (
        <Table label="Platform audit log">
          <thead>
            <tr>
              <Th className="w-36">When</Th>
              <Th>Who</Th>
              <Th>What</Th>
              <Th className="w-28">Outcome</Th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <Tr key={entry.seq}>
                <Td className="text-muted" title={formatDateTime(entry.at)}>
                  {formatRelative(entry.at)}
                </Td>
                <Td>{actor(entry)}</Td>
                <Td>
                  {humanize(entry.action.split(".").slice(1).join(".") || entry.action)}
                  {entry.target?.name ? <span className="block text-xs text-subtle">{String(entry.target.name)}</span> : null}
                </Td>
                <Td>
                  <Badge tone={entry.outcome === "success" ? "success" : entry.outcome === "denied" ? "warning" : "danger"}>{humanize(entry.outcome)}</Badge>
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  )
}

export function PlatformPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Platform"
        title="Platform console"
        description="Run this UTDRS deployment: its organisations, who administers them, and who runs the platform."
      />
      <Organisations />
      <div className="grid gap-6 xl:grid-cols-2">
        <PlatformAdmins />
        <PlatformAuditLog />
      </div>
    </div>
  )
}
