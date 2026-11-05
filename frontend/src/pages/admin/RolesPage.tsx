import { Plus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import type { Schemas } from "@/api/client"
import { useDeleteRole, useRoleCatalogue, useRoles, useSaveRole } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"

type CustomRole = Schemas["CustomRole"]
type Area = Schemas["PermissionArea"]
type Access = "none" | "read" | "write"

function accessOf(permissions: readonly string[], area: string): Access {
  if (permissions.includes(`${area}:write`)) return "write"
  if (permissions.includes(`${area}:read`)) return "read"
  return "none"
}

function permissionsFrom(access: Record<string, Access>): string[] {
  return Object.entries(access).flatMap(([area, level]) => (level === "write" ? [`${area}:write`] : level === "read" ? [`${area}:read`] : []))
}

/** One row per area: none, see, or see and change (where people other than administrators may change it). */
function PermissionGrid({ areas, access, onChange }: { areas: Area[]; access: Record<string, Access>; onChange: (area: string, level: Access) => void }) {
  return (
    <fieldset className="space-y-1">
      <legend className="mb-2 text-sm font-medium">Permissions</legend>
      {areas.map((area) => {
        const levels: Array<[Access, string]> = [["none", "None"], ["read", "See"], ...(area.write ? [["write", "See and change"] as [Access, string]] : [])]
        return (
          <div key={area.area} role="radiogroup" aria-label={area.label} className="flex flex-wrap items-center gap-3 rounded-lg border border-border px-3 py-2">
            <span className="min-w-36 flex-1">
              <span className="block text-sm font-medium">{area.label}</span>
              <span className="block text-xs text-muted">
                {access[area.area] === "write" ? area.write : access[area.area] === "read" ? area.read : area.write ? `${area.read}; ${area.write.toLowerCase()}` : `${area.read} (changing is for administrators)`}
              </span>
            </span>
            {levels.map(([level, label]) => (
              <label key={level} className="flex items-center gap-1.5 text-xs">
                <input
                  type="radio"
                  name={`access-${area.area}`}
                  checked={(access[area.area] ?? "none") === level}
                  onChange={() => onChange(area.area, level)}
                  className="size-3.5"
                />
                {label}
              </label>
            ))}
          </div>
        )
      })}
    </fieldset>
  )
}

function RoleDialog({ role, open, onClose, areas }: { role: CustomRole | null; open: boolean; onClose: () => void; areas: Area[] }) {
  const save = useSaveRole()
  const [access, setAccess] = useState<Record<string, Access>>(() =>
    Object.fromEntries(areas.map((area) => [area.area, accessOf(role?.permissions ?? [], area.area)])),
  )
  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title={role ? `Change ${role.name}` : "New role"}
      description={role ? "Everyone with this role has the new permissions at once." : "Choose what people with this role can see and change. Running the organisation stays with administrators."}
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        save.mutate(
          { id: role?.id, name: String(data.get("name") ?? "").trim(), description: String(data.get("description") ?? "").trim(), permissions: permissionsFrom(access) },
          {
            onSuccess: (saved) => {
              toast.success(role ? `${saved.name} saved` : `${saved.name} created`)
              onClose()
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            {role ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" required>
            {(id) => <Input id={id} name="name" required maxLength={60} defaultValue={role?.name} placeholder="Triage" />}
          </Field>
          <Field label="Description">
            {(id) => <Input id={id} name="description" maxLength={300} defaultValue={role?.description} placeholder="First line: triages alerts" />}
          </Field>
        </div>
        <PermissionGrid areas={areas} access={access} onChange={(area, level) => setAccess((current) => ({ ...current, [area]: level }))} />
      </div>
    </Dialog>
  )
}

function Summary({ permissions, areas }: { permissions: readonly string[]; areas: Area[] }) {
  const parts = areas
    .map((area) => [area.label, accessOf(permissions, area.area)] as const)
    .filter(([, level]) => level !== "none")
    .map(([label, level]) => `${label}${level === "write" ? " (change)" : ""}`)
  return <p className="text-xs text-muted">{parts.length ? parts.join(" · ") : "Nothing yet: only their own profile"}</p>
}

export function RolesPage() {
  const catalogue = useRoleCatalogue()
  const roles = useRoles()
  const remove = useDeleteRole()
  const [editing, setEditing] = useState<CustomRole | "new" | null>(null)

  if (catalogue.isPending || roles.isPending) return <SkeletonRows rows={4} columns={3} />
  if (catalogue.isError) return <ErrorState error={catalogue.error} onRetry={() => void catalogue.refetch()} />
  if (roles.isError) return <ErrorState error={roles.error} onRetry={() => void roles.refetch()} />
  const areas = catalogue.data.areas

  return (
    <div className="space-y-6">
      <PageHeader
        title="Roles"
        description="What people can see and do. Give someone a role on the Users page."
        actions={
          <Button variant="primary" onClick={() => setEditing("new")}>
            <Plus className="size-4" aria-hidden /> New role
          </Button>
        }
      />
      <Card title="Your roles" description="Each a chosen part of what an analyst can do." bodyClassName="p-0">
        {!roles.data.length ? (
          <EmptyState title="No roles of your own yet">For example, a first-line role that triages alerts but cannot run response actions.</EmptyState>
        ) : (
          <ul className="divide-y divide-border" aria-label="Your roles">
            {roles.data.map((role) => (
              <li key={role.id} className="flex flex-wrap items-start gap-3 px-5 py-3">
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="text-sm font-medium">
                    {role.name}
                    <Badge className="ml-2">{role.people === 1 ? "1 person" : `${role.people} people`}</Badge>
                  </p>
                  {role.description && <p className="text-sm text-muted">{role.description}</p>}
                  <Summary permissions={role.permissions} areas={areas} />
                </div>
                <Button size="sm" onClick={() => setEditing(role)}>
                  Change
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(role.id, { onSuccess: () => toast.success(`${role.name} deleted`), onError: (error) => toast.error(error.message) })}
                >
                  Delete
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Built-in roles" bodyClassName="p-0">
        <ul className="divide-y divide-border">
          {catalogue.data.built_in.map((role) => (
            <li key={role.role} className="space-y-1 px-5 py-3">
              <p className="text-sm font-medium">{role.name}</p>
              <p className="text-sm text-muted">{role.description}</p>
            </li>
          ))}
        </ul>
      </Card>
      {editing && (
        <RoleDialog key={editing === "new" ? "new" : editing.id} role={editing === "new" ? null : editing} open onClose={() => setEditing(null)} areas={areas} />
      )}
    </div>
  )
}
