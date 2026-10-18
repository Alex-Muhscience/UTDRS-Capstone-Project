import { useNotificationLog } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"
import type { Tone } from "@/lib/tones"
import { useUrlFilters } from "@/lib/useUrlFilters"

const STATUSES = ["queued", "sending", "sent", "failed", "skipped"] as const
const TONES: Record<string, Tone> = { queued: "neutral", sending: "accent", sent: "success", failed: "danger", skipped: "warning" }
const KINDS: Record<string, string> = { case_opened: "New case", approval_needed: "Approval needed", action_finished: "Action taken" }

export function EmailLogPage() {
  const { filters, page, setFilter, setPage } = useUrlFilters(["status"] as const)
  const status = (STATUSES as readonly string[]).includes(filters.status) ? (filters.status as (typeof STATUSES)[number]) : undefined
  const log = useNotificationLog({ status, page })

  return (
    <>
      <PageHeader
        title="Email log"
        description="Every email UTDRS sent your people, or did not send and why. Failed sends are retried for about an hour and a quarter before they are given up."
      />
      <Card bodyClassName="p-0">
        <div className="flex border-b border-border p-4">
          <Select aria-label="Status" value={filters.status} onChange={(event) => setFilter("status", event.target.value)} options={STATUSES} placeholder="Every status" className="sm:w-60" />
        </div>
        {log.isPending ? (
          <SkeletonRows />
        ) : log.isError ? (
          <ErrorState error={log.error} onRetry={() => void log.refetch()} />
        ) : log.data.rows.length === 0 ? (
          <EmptyState title="No emails yet" />
        ) : (
          <Table label="Email log">
            <thead>
              <tr>
                <Th className="w-36">When</Th>
                <Th>To</Th>
                <Th>Subject</Th>
                <Th className="w-28">Status</Th>
              </tr>
            </thead>
            <tbody>
              {log.data.rows.map((entry) => (
                <Tr key={entry.id}>
                  <Td className="text-muted" title={formatDateTime(entry.created_at)}>
                    {formatRelative(entry.created_at)}
                  </Td>
                  <Td className="max-w-0 truncate">{entry.email}</Td>
                  <Td className="max-w-0">
                    <span className="block truncate font-medium">{entry.subject}</span>
                    <span className="block truncate text-xs text-subtle">
                      {KINDS[entry.kind] ?? entry.kind}
                      {entry.error ? ` · ${entry.error}` : ""}
                    </span>
                  </Td>
                  <Td>
                    <Badge tone={TONES[entry.status] ?? "neutral"}>
                      {entry.status === "queued" && entry.attempts ? `Retrying (${entry.attempts})` : humanize(entry.status)}
                    </Badge>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {log.data && <Pagination page={page} hasMore={log.data.hasMore} onPage={setPage} fetching={log.isFetching} />}
      </Card>
    </>
  )
}
