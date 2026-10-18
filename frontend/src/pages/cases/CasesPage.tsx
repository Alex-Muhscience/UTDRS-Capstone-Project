import { Link, useNavigate } from "react-router"

import { displayName, useCases, useUsers } from "@/api/queries"
import { useUser } from "@/auth/context"
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { cx } from "@/lib/cx"
import { formatDateTime, formatRelative } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

const VIEWS = [
  { value: "active", label: "Active" },
  { value: "", label: "All" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
  { value: "closed", label: "Closed" },
]

export function CasesPage() {
  const me = useUser()
  const navigate = useNavigate()
  const { filters, page, setFilter, setPage } = useUrlFilters(["view"] as const)
  // Active cases unless another view is chosen; "all" is an explicit empty choice.
  const view = filters.view === "" ? "active" : filters.view === "all" ? "" : filters.view
  const cases = useCases({ status: view, page })
  const users = useUsers()
  const owner = (id: string | null | undefined) => {
    if (!id) return "Unassigned"
    if (id === me.id) return "You"
    const person = users.data?.find((candidate) => candidate.id === id)
    return person ? displayName(person) : "—"
  }

  return (
    <>
      <PageHeader
        title="Cases"
        description="Alerts about the same user, device, address or sender, grouped so they are worked once. Each has an owner, a deadline from its priority, and a timeline."
      />
      <Card bodyClassName="p-0">
        <div role="tablist" aria-label="Cases" className="flex flex-wrap gap-1 border-b border-border p-4">
          {VIEWS.map((option) => {
            const value = option.value === "" ? "all" : option.value === "active" ? "" : option.value
            const selected = filters.view === value
            return (
              <button
                key={option.label}
                type="button"
                role="tab"
                aria-selected={selected}
                onClick={() => setFilter("view", value)}
                className={cx(
                  "rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
                  selected ? "bg-surface-3 text-fg" : "text-muted hover:bg-surface-2 hover:text-fg",
                )}
              >
                {option.label}
              </button>
            )
          })}
        </div>
        {cases.isPending ? (
          <SkeletonRows />
        ) : cases.isError ? (
          <ErrorState error={cases.error} onRetry={() => void cases.refetch()} />
        ) : cases.data.rows.length === 0 ? (
          <EmptyState title={view === "active" ? "No active cases" : "No cases here"}>
            {view === "active" ? "When the detectors raise an alert, it opens a case or joins one." : "Try another view."}
          </EmptyState>
        ) : (
          <Table label="Cases">
            <thead>
              <tr>
                <Th className="w-28">Priority</Th>
                <Th>Case</Th>
                <Th className="w-32">Status</Th>
                <Th className="w-32">Owner</Th>
                <Th className="w-36">Due</Th>
                <Th className="w-32">Last activity</Th>
              </tr>
            </thead>
            <tbody>
              {cases.data.rows.map((item) => (
                <Tr key={item.id} onClick={() => navigate(`/cases/${item.id}`)}>
                  <Td>
                    <SeverityBadge severity={item.priority} />
                  </Td>
                  <Td className="max-w-0">
                    <Link
                      to={`/cases/${item.id}`}
                      className="block truncate font-medium hover:text-accent"
                      onClick={(event) => event.stopPropagation()}
                    >
                      {item.title}
                    </Link>
                    <span className="block truncate text-xs text-subtle">
                      {item.alert_ids.length} alert{item.alert_ids.length === 1 ? "" : "s"}
                      {item.entities.length > 0 && ` · ${item.entities.slice(0, 3).map((entity) => entity.name ?? entity.value).join(", ")}`}
                    </span>
                  </Td>
                  <Td>
                    <StatusBadge status={item.status} />
                  </Td>
                  <Td className="max-w-0 truncate text-muted">{owner(item.owner_id)}</Td>
                  <Td title={formatDateTime(item.due_at)}>
                    {item.breached ? <Badge tone="danger">Overdue</Badge> : <span className="text-muted">{formatRelative(item.due_at)}</span>}
                  </Td>
                  <Td className="text-muted" title={formatDateTime(item.last_seen)}>
                    {formatRelative(item.last_seen)}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {cases.data && <Pagination page={page} hasMore={cases.data.hasMore} onPage={setPage} fetching={cases.isFetching} />}
      </Card>
    </>
  )
}
