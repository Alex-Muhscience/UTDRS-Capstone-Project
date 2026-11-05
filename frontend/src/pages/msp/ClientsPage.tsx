import { Plus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { useCreateClient, useMspAlerts, useMspOverview } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { useSwitchOrganisation } from "@/lib/useSwitchOrganisation"
import { Badge, SeverityBadge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatNumber, formatRelative, humanize } from "@/lib/format"
import { NotFoundPage } from "@/pages/errors/NotFoundPage"
import { OneTimePassword } from "@/pages/platform/PlatformPage"

function NewClientDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (username: string, password: string) => void }) {
  const create = useCreateClient()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Add a client"
      description="A new organisation your team manages. Give it an administrator of its own if someone there should sign in too; you can leave that empty and run it yourselves."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const field = (name: string) => String(data.get(name) ?? "").trim() || undefined
        create.mutate(
          { name: field("name") ?? "", admin_username: field("admin_username"), admin_email: field("admin_email") },
          {
            onSuccess: (result) => {
              onClose()
              toast.success(`${result.organisation.name} added`)
              if (result.administrator && result.temporary_password) onCreated(result.administrator.username, result.temporary_password)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Add
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Organisation name" required className="sm:col-span-2">
          {(id) => <Input id={id} name="name" required maxLength={100} />}
        </Field>
        <Field label="Their administrator's username" hint="Optional">
          {(id) => <Input id={id} name="admin_username" minLength={3} maxLength={50} autoComplete="off" />}
        </Field>
        <Field label="Their administrator's email" hint="Optional">
          {(id) => <Input id={id} name="admin_email" type="email" autoComplete="off" />}
        </Field>
      </div>
    </Dialog>
  )
}

function OpenAlerts() {
  const alerts = useMspAlerts()
  const switchTo = useSwitchOrganisation()
  return (
    <Card title="Open alerts across clients" description="Most severe and newest first. Opening one switches to its organisation." bodyClassName="p-0">
      {alerts.isPending ? (
        <SkeletonRows rows={3} columns={4} />
      ) : alerts.isError ? (
        <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />
      ) : !alerts.data.length ? (
        <p className="px-5 py-4 text-sm text-muted">No open alerts in any client.</p>
      ) : (
        <Table label="Open alerts across clients">
          <thead>
            <tr>
              <Th className="w-28">Severity</Th>
              <Th>Alert</Th>
              <Th>Organisation</Th>
              <Th className="w-32">Raised</Th>
            </tr>
          </thead>
          <tbody>
            {alerts.data.map((alert) => (
              <Tr key={alert.id} onClick={() => switchTo(alert.organisation_id, `/alerts/${alert.id}`)}>
                <Td>
                  <SeverityBadge severity={alert.severity} />
                </Td>
                <Td className="max-w-0 truncate font-medium">{alert.title}</Td>
                <Td className="text-muted">{alert.organisation}</Td>
                <Td className="text-muted" title={formatDateTime(alert.created_at)}>
                  {formatRelative(alert.created_at)}
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  )
}

export function ClientsPage() {
  const overview = useMspOverview()
  const isAdmin = useIsAdmin()
  const switchTo = useSwitchOrganisation()
  const [adding, setAdding] = useState(false)
  const [created, setCreated] = useState<{ username: string; password: string } | null>(null)

  if (overview.isPending) return <SkeletonRows rows={4} columns={5} />
  if (overview.isError) return <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
  if (!overview.data.msp) return <NotFoundPage />
  const { clients, organisation, role_in_clients } = overview.data

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={organisation}
        title="Clients"
        description={`The organisations ${organisation} looks after. You work in each as ${role_in_clients === "viewer" ? "read-only" : humanize(role_in_clients ?? "").toLowerCase()}, and each sees what you do in its audit log.`}
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setAdding(true)}>
              <Plus className="size-4" aria-hidden /> Add a client
            </Button>
          )
        }
      />
      <Card bodyClassName="p-0" title="Organisations">
        {!clients.length ? (
          <EmptyState title="No clients yet">{isAdmin ? "Add one, or ask the platform's operator to assign an existing organisation to you." : "Your administrators can add them."}</EmptyState>
        ) : (
          <Table label="Clients">
            <thead>
              <tr>
                <Th>Organisation</Th>
                <Th className="w-28">Urgent alerts</Th>
                <Th className="w-24 text-right">Open alerts</Th>
                <Th className="w-28 text-right">Events (7 days)</Th>
                <Th className="w-24 text-right">Connectors</Th>
                <Th className="w-32">Last sign-in</Th>
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <Tr key={client.id} onClick={() => switchTo(client.id)}>
                  <Td>
                    <button type="button" className="font-medium hover:underline" onClick={(event) => { event.stopPropagation(); switchTo(client.id) }}>
                      {client.name}
                    </button>
                    {client.status !== "active" && <Badge tone="danger" className="ml-2">{humanize(client.status)}</Badge>}
                  </Td>
                  <Td>{client.urgent_alerts ? <Badge tone="danger">{formatNumber(client.urgent_alerts)}</Badge> : <span className="text-muted">None</span>}</Td>
                  <Td className="text-right tabular-nums">{formatNumber(client.open_alerts)}</Td>
                  <Td className="text-right tabular-nums">{formatNumber(client.events_last_week)}</Td>
                  <Td className="text-right tabular-nums">{formatNumber(client.connectors)}</Td>
                  <Td className="text-muted" title={formatDateTime(client.last_sign_in)}>
                    {client.last_sign_in ? formatRelative(client.last_sign_in) : "Never"}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <OpenAlerts />
      <NewClientDialog open={adding} onClose={() => setAdding(false)} onCreated={(username, password) => setCreated({ username, password })} />
      <OneTimePassword username={created?.username ?? ""} password={created?.password ?? null} onClose={() => setCreated(null)} />
    </div>
  )
}
