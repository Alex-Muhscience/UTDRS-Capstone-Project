import { useAuditLog } from "@/api/queries"
import type { Schemas } from "@/api/client"
import { Badge } from "@/components/ui/Badge"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"

type Entry = Schemas["AuditEntry"]

function who(entry: Entry): string {
  const name = typeof entry.actor.name === "string" && entry.actor.name ? entry.actor.name : null
  if (entry.actor.type === "operator") return name ?? "An operator"
  if (entry.actor.type === "anonymous") return name ? `${name} (not signed in)` : "Not signed in"
  return name ?? humanize(String(entry.actor.type))
}

export function AuditLogPage() {
  const log = useAuditLog()
  const entries = (log.data ?? []) as unknown as Entry[]
  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        description="Operators' sign-ins and everything done in this console, and sign-in attempts to accounts that do not exist. What was done to an organisation is also in its own log."
      />
      <Card bodyClassName="p-0">
        {log.isPending ? (
          <SkeletonRows rows={5} columns={4} />
        ) : log.isError ? (
          <ErrorState error={log.error} onRetry={() => void log.refetch()} />
        ) : !entries.length ? (
          <EmptyState title="Nothing recorded yet" />
        ) : (
          <Table label="Audit log">
            <thead>
              <tr>
                <Th className="w-36">When</Th>
                <Th>Who</Th>
                <Th>What</Th>
                <Th className="w-28">Outcome</Th>
                <Th className="w-36">From</Th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <Tr key={entry.seq}>
                  <Td className="text-muted" title={formatDateTime(entry.at)}>
                    {formatRelative(entry.at)}
                  </Td>
                  <Td>{who(entry)}</Td>
                  <Td>
                    {humanize(entry.action.split(".").slice(1).join(".") || entry.action)}
                    {entry.target?.name ? <span className="block text-xs text-subtle">{String(entry.target.name)}</span> : null}
                  </Td>
                  <Td>
                    <Badge tone={entry.outcome === "success" ? "success" : entry.outcome === "denied" ? "warning" : "danger"}>{humanize(entry.outcome)}</Badge>
                  </Td>
                  <Td className="font-mono text-xs text-muted">{entry.address ?? "—"}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  )
}
