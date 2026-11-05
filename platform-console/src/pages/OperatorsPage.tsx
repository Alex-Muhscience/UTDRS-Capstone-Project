import { UserPlus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { useAddOperator, useMe, useOperators, useResetOperator, useSetOperatorActive } from "@/api/queries"
import { OneTimePassword } from "@/components/OneTimePassword"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative } from "@/lib/format"

function AddOperatorDialog({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: (username: string, password: string) => void }) {
  const add = useAddOperator()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add an operator"
      description="They get a temporary password; at first sign-in they set up an authenticator and choose their own password."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        add.mutate(
          { username: String(data.get("username") ?? "").trim(), email: String(data.get("email") ?? "").trim() },
          {
            onSuccess: (result) => {
              onClose()
              onAdded(result.operator.username, result.temporary_password)
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
          {(id) => <Input id={id} name="username" required minLength={3} maxLength={100} autoComplete="off" />}
        </Field>
        <Field label="Email" required>
          {(id) => <Input id={id} name="email" type="email" required autoComplete="off" />}
        </Field>
      </div>
    </Dialog>
  )
}

export function OperatorsPage() {
  const me = useMe()
  const operators = useOperators()
  const setActive = useSetOperatorActive()
  const reset = useResetOperator()
  const [adding, setAdding] = useState(false)
  const [password, setPassword] = useState<{ username: string; password: string } | null>(null)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Operators"
        description="The people who run this deployment. They are not members of any organisation, and always sign in with an authenticator."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <UserPlus className="size-4" aria-hidden /> Add an operator
          </Button>
        }
      />
      <Card bodyClassName="p-0">
        {operators.isPending ? (
          <SkeletonRows rows={2} columns={4} />
        ) : operators.isError ? (
          <ErrorState error={operators.error} onRetry={() => void operators.refetch()} />
        ) : (
          <Table label="Operators">
            <thead>
              <tr>
                <Th>Operator</Th>
                <Th className="w-48">Status</Th>
                <Th className="w-36">Last sign-in</Th>
                <Th className="w-56">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {operators.data.map((operator) => {
                const isMe = operator.id === me.data?.id
                return (
                  <Tr key={operator.id}>
                    <Td>
                      <span className="block font-medium">
                        {operator.username}
                        {isMe && <span className="ml-2 text-xs text-subtle">(you)</span>}
                      </span>
                      <span className="block text-xs text-subtle">{operator.email}</span>
                    </Td>
                    <Td className="space-x-1">
                      {operator.active ? <Badge tone="success">Active</Badge> : <Badge>Deactivated</Badge>}
                      {!operator.mfa && <Badge tone="warning">Authenticator not set up</Badge>}
                    </Td>
                    <Td className="text-muted" title={formatDateTime(operator.last_sign_in)}>
                      {operator.last_sign_in ? formatRelative(operator.last_sign_in) : "Never"}
                    </Td>
                    <Td className="text-right">
                      {!isMe && (
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={reset.isPending}
                            title="A new temporary password, and their authenticator cleared (a lost phone)"
                            onClick={() =>
                              reset.mutate(operator.id, {
                                onSuccess: (result) => setPassword({ username: result.operator.username, password: result.temporary_password }),
                                onError: (error) => toast.error(error.message),
                              })
                            }
                          >
                            Reset
                          </Button>
                          <Button
                            size="sm"
                            variant={operator.active ? "danger" : undefined}
                            disabled={setActive.isPending}
                            onClick={() =>
                              setActive.mutate(
                                { id: operator.id, active: !operator.active },
                                {
                                  onSuccess: () => toast.success(`${operator.username} ${operator.active ? "deactivated" : "reactivated"}`),
                                  onError: (error) => toast.error(error.message),
                                },
                              )
                            }
                          >
                            {operator.active ? "Deactivate" : "Reactivate"}
                          </Button>
                        </div>
                      )}
                    </Td>
                  </Tr>
                )
              })}
            </tbody>
          </Table>
        )}
      </Card>
      <AddOperatorDialog open={adding} onClose={() => setAdding(false)} onAdded={(username, temporary) => setPassword({ username, password: temporary })} />
      <OneTimePassword username={password?.username ?? ""} password={password?.password ?? null} onClose={() => setPassword(null)} />
    </div>
  )
}
