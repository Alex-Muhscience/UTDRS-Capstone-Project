import { Plus } from "lucide-react"
import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { toast } from "sonner"

import { useCreateOrganisation, useOrganisations } from "@/api/queries"
import { OneTimePassword } from "@/components/OneTimePassword"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatNumber, formatRelative, humanize } from "@/lib/format"

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

  if (organisations.isError) return <ErrorState error={organisations.error} onRetry={() => void organisations.refetch()} />
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
                <Tr key={organisation.id} onClick={() => void navigate(`/organisations/${organisation.id}`)}>
                  <Td>
                    <Link to={`/organisations/${organisation.id}`} className="font-medium hover:underline" onClick={(event) => event.stopPropagation()}>
                      {organisation.name}
                    </Link>
                    {organisation.default && <span className="ml-2 text-xs text-subtle">platform's own</span>}
                    {organisation.msp && <Badge tone="accent" className="ml-2">MSP</Badge>}
                    {organisation.managed_by_name && <span className="ml-2 text-xs text-subtle">managed by {organisation.managed_by_name}</span>}
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
          if (tenantId) void navigate(`/organisations/${tenantId}`)
        }}
      />
    </>
  )
}

export function OrganisationsPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Organisations" description="Every organisation on this deployment: their activity, and who administers them." />
      <Organisations />
    </div>
  )
}
