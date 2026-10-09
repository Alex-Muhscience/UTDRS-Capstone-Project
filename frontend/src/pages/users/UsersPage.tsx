import { KeyRound, UserPlus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import type { UserWithPassword } from "@/api/client"
import { displayName, useCreateUser, useResetPassword, useUpdateUser, useUsers } from "@/api/queries"
import { useUser } from "@/auth/context"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative } from "@/lib/format"

import { TemporaryPasswordDialog } from "./TemporaryPasswordDialog"

const ROLES = [
  { value: "analyst", label: "Analyst" },
  { value: "admin", label: "Administrator" },
]

function NewUserDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (result: UserWithPassword) => void }) {
  const create = useCreateUser()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add a user"
      description="They get a temporary password to sign in with, then change it on their profile."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const value = (name: string) => String(data.get(name) ?? "").trim()
        create.mutate(
          {
            username: value("username"),
            email: value("email"),
            firstName: value("firstName") || null,
            lastName: value("lastName") || null,
            role: value("role") === "admin" ? "admin" : "analyst",
          },
          {
            onSuccess: (result) => {
              onClose()
              onCreated(result)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Add user
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="First name">{(id) => <Input id={id} name="firstName" />}</Field>
        <Field label="Last name">{(id) => <Input id={id} name="lastName" />}</Field>
        <Field label="Username" required>
          {(id) => <Input id={id} name="username" required minLength={3} autoComplete="off" />}
        </Field>
        <Field label="Role" required>
          {(id) => <Select id={id} name="role" options={ROLES} defaultValue="analyst" />}
        </Field>
        <Field label="Email" required className="sm:col-span-2">
          {(id) => <Input id={id} name="email" type="email" required autoComplete="off" />}
        </Field>
      </div>
    </Dialog>
  )
}

export function UsersPage() {
  const me = useUser()
  const users = useUsers()
  const update = useUpdateUser()
  const reset = useResetPassword()
  const [adding, setAdding] = useState(false)
  const [password, setPassword] = useState<UserWithPassword | null>(null)

  function change(userId: string, name: string, changes: { role?: "admin" | "analyst"; active?: boolean }) {
    update.mutate(
      { userId, ...changes },
      {
        onSuccess: () =>
          toast.success(
            changes.role
              ? `${name} is now ${changes.role === "admin" ? "an administrator" : "an analyst"}`
              : `${name} is ${changes.active ? "reactivated" : "deactivated"}`,
          ),
        onError: (error) => toast.error(error.message),
      },
    )
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Who can sign in, and what they can do. Administrators manage users, detection rules and simulations; analysts triage alerts and work with events and assets."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <UserPlus className="size-4" aria-hidden /> Add user
          </Button>
        }
      />
      <Card bodyClassName="p-0">
        {users.isPending ? (
          <SkeletonRows />
        ) : users.isError ? (
          <ErrorState error={users.error} onRetry={() => void users.refetch()} />
        ) : users.data.length === 0 ? (
          <EmptyState title="No users" />
        ) : (
          <Table label="Users">
            <thead>
              <tr>
                <Th>Person</Th>
                <Th className="w-44">Role</Th>
                <Th className="w-32">Status</Th>
                <Th className="w-36">Last sign-in</Th>
                <Th className="w-56">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {users.data.map((user) => {
                const name = displayName(user)
                const isMe = user.id === me.id
                return (
                  <Tr key={user.id}>
                    <Td className="max-w-0">
                      <span className="block truncate font-medium">
                        {name}
                        {isMe && <span className="ml-2 text-xs text-subtle">(you)</span>}
                      </span>
                      <span className="block truncate text-xs text-subtle">
                        {user.username} · {user.email}
                      </span>
                    </Td>
                    <Td>
                      <Select
                        aria-label={`Role of ${name}`}
                        value={user.role}
                        options={ROLES}
                        disabled={isMe || update.isPending}
                        title={isMe ? "Another administrator can change your role" : undefined}
                        onChange={(event) => change(user.id, name, { role: event.target.value === "admin" ? "admin" : "analyst" })}
                        className="h-8 w-40 text-xs"
                      />
                    </Td>
                    <Td>{user.active ? <Badge tone="success">Active</Badge> : <Badge>Deactivated</Badge>}</Td>
                    <Td className="text-muted" title={formatDateTime(user.lastLogin)}>
                      {user.lastLogin ? formatRelative(user.lastLogin) : "Never"}
                    </Td>
                    <Td className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={reset.isPending}
                          onClick={() =>
                            reset.mutate(user.id, {
                              onSuccess: setPassword,
                              onError: (error) => toast.error(error.message),
                            })
                          }
                        >
                          <KeyRound className="size-3.5" aria-hidden /> Reset password
                        </Button>
                        {!isMe && (
                          <Button
                            size="sm"
                            variant={user.active ? "danger" : "secondary"}
                            disabled={update.isPending}
                            onClick={() => change(user.id, name, { active: !user.active })}
                          >
                            {user.active ? "Deactivate" : "Reactivate"}
                          </Button>
                        )}
                      </div>
                    </Td>
                  </Tr>
                )
              })}
            </tbody>
          </Table>
        )}
      </Card>
      <NewUserDialog open={adding} onClose={() => setAdding(false)} onCreated={setPassword} />
      <TemporaryPasswordDialog result={password} onClose={() => setPassword(null)} />
    </>
  )
}
