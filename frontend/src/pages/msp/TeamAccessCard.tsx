import { useState } from "react"
import { toast } from "sonner"

import type { Schemas } from "@/api/client"
import { useAssignClients, useMspStaff, useSetStaffAccess } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { SkeletonRows } from "@/components/ui/States"

type Client = Schemas["OrganisationSummary"]
type StaffMember = Schemas["StaffMember"]

const ROLE_NAMES: Record<string, string> = { analyst: "Analyst", viewer: "Read-only", admin: "Administrator" }

function AssignDialog({ person, clients, onClose }: { person: StaffMember | null; clients: Client[]; onClose: () => void }) {
  const assign = useAssignClients()
  return (
    <Dialog
      open={person !== null}
      onClose={onClose}
      title={person ? `${person.username}'s clients` : ""}
      description="The organisations they can work in. They see no others, in the list or anywhere else."
      onSubmit={(event) => {
        if (!person) return
        const chosen = new FormData(event.currentTarget).getAll("clients").map(String)
        assign.mutate(
          { userId: person.id, clients: chosen },
          {
            onSuccess: () => {
              toast.success(`${person.username} now works in ${chosen.length} ${chosen.length === 1 ? "client" : "clients"}`)
              onClose()
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={assign.isPending}>
            Save
          </Button>
        </>
      }
    >
      {person && (
        <div className="grid gap-2 sm:grid-cols-2">
          {clients.map((client) => (
            <label key={client.id} className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm">
              <input type="checkbox" name="clients" value={client.id} defaultChecked={person.clients.includes(client.id)} className="size-4" />
              {client.name}
            </label>
          ))}
        </div>
      )}
    </Dialog>
  )
}

/** For a service provider's administrators: whether staff reach every client, or only those assigned to them. */
export function TeamAccessCard({ staffAccess, clients }: { staffAccess: string; clients: Client[] }) {
  const setAccess = useSetStaffAccess()
  const assigned = staffAccess === "assigned"
  const staff = useMspStaff(assigned)
  const [editing, setEditing] = useState<StaffMember | null>(null)
  const names = new Map(clients.map((client) => [client.id, client.name]))
  const choose = (value: "all" | "assigned") =>
    setAccess.mutate(value, {
      onSuccess: () => toast.success(value === "all" ? "Your staff now reach every client" : "Your staff now reach only the clients assigned to them"),
      onError: (error) => toast.error(error.message),
    })

  return (
    <Card title="Team access" description="Which clients your staff can work in. Your administrators always reach every client." bodyClassName="p-0">
      <div role="radiogroup" aria-label="Team access" className="grid gap-2 px-5 py-4 sm:grid-cols-2">
        {(
          [
            ["all", "Every client", "Everyone in your team works in every client."],
            ["assigned", "Only their clients", "Each person works only in the clients you assign them."],
          ] as const
        ).map(([value, label, help]) => (
          <label key={value} className="flex items-start gap-2 rounded-lg border border-border px-3 py-2 text-sm">
            <input type="radio" name="staff-access" checked={staffAccess === value} disabled={setAccess.isPending} onChange={() => choose(value)} className="mt-0.5" />
            <span>
              <span className="block font-medium">{label}</span>
              <span className="block text-xs text-muted">{help}</span>
            </span>
          </label>
        ))}
      </div>
      {assigned && (
        <div className="border-t border-border">
          {staff.isPending ? (
            <SkeletonRows rows={2} columns={3} />
          ) : (
            <ul className="divide-y divide-border" aria-label="Staff and their clients">
              {(staff.data ?? [])
                .filter((person) => person.role !== "admin")
                .map((person) => (
                  <li key={person.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                    <span className="min-w-40 font-medium">{person.username}</span>
                    <Badge>{ROLE_NAMES[person.role ?? ""] ?? "Custom role"}</Badge>
                    <span className="min-w-0 flex-1 truncate text-muted">
                      {person.clients.length ? person.clients.map((id) => names.get(id) ?? "a released client").join(", ") : "No clients yet"}
                    </span>
                    <Button size="sm" onClick={() => setEditing(person)}>
                      Assign clients
                    </Button>
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}
      <AssignDialog person={editing} clients={clients} onClose={() => setEditing(null)} />
    </Card>
  )
}
