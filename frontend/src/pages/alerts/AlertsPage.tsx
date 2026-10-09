import { Link, useNavigate } from "react-router"

import { displayName, useAlerts, useUsers } from "@/api/queries"
import { useUser } from "@/auth/context"
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { SearchInput } from "@/components/ui/SearchInput"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { ALERT_STATUSES, SEVERITIES } from "@/lib/constants"
import { cx } from "@/lib/cx"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

const FILTERS = ["status", "severity", "q"] as const

export function AlertsPage() {
  const user = useUser()
  const navigate = useNavigate()
  const { filters, page, setFilter, setPage } = useUrlFilters(FILTERS)
  const alerts = useAlerts({ status: filters.status, severity: filters.severity, search: filters.q, page })
  const users = useUsers()
  const nameOf = (userId: string) => {
    if (userId === user.id) return "You"
    const person = users.data?.find((candidate) => candidate.id === userId)
    return person ? displayName(person) : "—"
  }
  const filtered = Boolean(filters.status || filters.severity || filters.q)

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Detections to triage. Alerts raised by the core engine link back to the event that triggered them."
      />

      <Card bodyClassName="p-0">
        <div className="flex flex-col gap-3 border-b border-border p-4 xl:flex-row xl:items-center">
          <div role="tablist" aria-label="Status" className="flex flex-wrap gap-1">
            {["", ...ALERT_STATUSES].map((status) => (
              <button
                key={status || "all"}
                type="button"
                role="tab"
                aria-selected={filters.status === status}
                onClick={() => setFilter("status", status)}
                className={cx(
                  "rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
                  filters.status === status ? "bg-surface-3 text-fg" : "text-muted hover:bg-surface-2 hover:text-fg",
                )}
              >
                {status ? humanize(status) : "All"}
              </button>
            ))}
          </div>
          <div className="flex gap-2 xl:ml-auto">
            <Select
              aria-label="Severity"
              value={filters.severity}
              onChange={(event) => setFilter("severity", event.target.value)}
              options={SEVERITIES}
              placeholder="Any severity"
              className="w-40"
            />
            <SearchInput
              value={filters.q}
              onChange={(value) => setFilter("q", value)}
              placeholder="Search alerts"
              className="w-full xl:w-64"
            />
          </div>
        </div>

        {alerts.isPending ? (
          <SkeletonRows />
        ) : alerts.isError ? (
          <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />
        ) : alerts.data.rows.length === 0 ? (
          <EmptyState title={filtered ? "No matching alerts" : "No alerts yet"}>
            {filtered
              ? "Try a different status, severity or search."
              : "Send a test event from the Events page to see the engine raise one."}
          </EmptyState>
        ) : (
          <Table label="Alerts">
            <thead>
              <tr>
                <Th className="w-28">Severity</Th>
                <Th>Alert</Th>
                <Th className="w-36">Status</Th>
                <Th className="w-32">Assignee</Th>
                <Th className="w-36">Raised</Th>
              </tr>
            </thead>
            <tbody>
              {alerts.data.rows.map((alert) => (
                <Tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)}>
                  <Td>
                    <SeverityBadge severity={alert.severity} />
                  </Td>
                  <Td className="max-w-0">
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="block truncate font-medium hover:text-accent"
                      onClick={(event) => event.stopPropagation()}
                    >
                      {alert.title}
                    </Link>
                    <span className="block truncate text-xs text-subtle">
                      {alert.source} · {humanize(alert.type)}
                    </span>
                  </Td>
                  <Td>
                    <StatusBadge status={alert.status} />
                  </Td>
                  <Td className="max-w-0 truncate text-muted">{alert.assigned_to ? nameOf(alert.assigned_to) : "—"}</Td>
                  <Td className="text-muted" title={formatDateTime(alert.created_at)}>
                    {formatRelative(alert.created_at)}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {alerts.data && <Pagination page={page} hasMore={alerts.data.hasMore} onPage={setPage} fetching={alerts.isFetching} />}
      </Card>
    </>
  )
}
