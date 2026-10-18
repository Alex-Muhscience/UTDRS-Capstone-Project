import { MailSearch, Send } from "lucide-react"
import { useState } from "react"
import { Link, useNavigate } from "react-router"

import { useEvents } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { SearchInput } from "@/components/ui/SearchInput"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { EVENT_TYPES } from "@/lib/constants"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

import { AnalysisBadge } from "./AnalysisBadge"
import { CheckEmailDialog } from "./CheckEmailDialog"
import { TestEventDialog } from "./TestEventDialog"

const FILTERS = ["type", "q"] as const

export function EventsPage() {
  const navigate = useNavigate()
  const [sending, setSending] = useState(false)
  const [checking, setChecking] = useState(false)
  const { filters, page, setFilter, setPage } = useUrlFilters(FILTERS)
  const events = useEvents({ eventType: filters.type, search: filters.q, page })
  const filtered = Boolean(filters.type || filters.q)

  return (
    <>
      <PageHeader
        title="Events"
        description="Security events received by the gateway, newest first, with the core engine's verdict on each."
        actions={
          <>
            <Button onClick={() => setChecking(true)}>
              <MailSearch className="size-4" aria-hidden /> Check an email
            </Button>
            <Button variant="primary" onClick={() => setSending(true)}>
              <Send className="size-4" aria-hidden /> Send test event
            </Button>
          </>
        }
      />

      <Card bodyClassName="p-0">
        <div className="flex flex-col gap-2 border-b border-border p-4 sm:flex-row">
          <Select
            aria-label="Event type"
            value={filters.type}
            onChange={(event) => setFilter("type", event.target.value)}
            options={EVENT_TYPES}
            placeholder="Any type"
            className="sm:w-44"
          />
          <SearchInput
            value={filters.q}
            onChange={(value) => setFilter("q", value)}
            placeholder="Search events"
            className="sm:ml-auto sm:w-72"
          />
        </div>

        {events.isPending ? (
          <SkeletonRows />
        ) : events.isError ? (
          <ErrorState error={events.error} onRetry={() => void events.refetch()} />
        ) : events.data.rows.length === 0 ? (
          <EmptyState
            title={filtered ? "No matching events" : "No events yet"}
            action={!filtered && <Button onClick={() => setSending(true)}>Send a test event</Button>}
          >
            {filtered
              ? "Try a different type or search."
              : "Events arrive from agents and integrations through the gateway's /events endpoint."}
          </EmptyState>
        ) : (
          <Table label="Events">
            <thead>
              <tr>
                <Th className="w-36">Time</Th>
                <Th className="w-32">Type</Th>
                <Th>Event</Th>
                <Th className="w-44">Network</Th>
                <Th className="w-36">Analysis</Th>
              </tr>
            </thead>
            <tbody>
              {events.data.rows.map((event) => (
                <Tr key={event.id} onClick={() => navigate(`/events/${event.id}`)}>
                  <Td className="text-muted" title={formatDateTime(event.timestamp)}>
                    {formatRelative(event.timestamp)}
                  </Td>
                  <Td>
                    <Badge>{humanize(event.event_type)}</Badge>
                  </Td>
                  <Td className="max-w-0">
                    <Link
                      to={`/events/${event.id}`}
                      className="block truncate font-medium hover:text-accent"
                      onClick={(clickEvent) => clickEvent.stopPropagation()}
                    >
                      {event.description}
                    </Link>
                    <span className="block truncate text-xs text-subtle">
                      {event.source}
                      {event.user_id && ` · ${event.user_id}`}
                    </span>
                  </Td>
                  <Td className="font-mono text-xs text-muted">
                    {event.source_ip || event.destination_ip ? `${event.source_ip ?? "?"} → ${event.destination_ip ?? "?"}` : "—"}
                  </Td>
                  <Td>
                    <AnalysisBadge event={event} />
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {events.data && <Pagination page={page} hasMore={events.data.hasMore} onPage={setPage} fetching={events.isFetching} />}
      </Card>

      <TestEventDialog open={sending} onClose={() => setSending(false)} />
      <CheckEmailDialog open={checking} onClose={() => setChecking(false)} />
    </>
  )
}
