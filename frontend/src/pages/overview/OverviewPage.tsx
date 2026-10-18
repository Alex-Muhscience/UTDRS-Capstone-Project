import { ArrowRight, Database, Radar, Server, ShieldAlert, type LucideIcon } from "lucide-react"
import type { ReactNode } from "react"
import { Link } from "react-router"

import {
  useAlertSummary,
  useDatabaseHealth,
  useDetectionStatus,
  useLatestAlerts,
  useRecentEvents,
} from "@/api/queries"
import { useUser } from "@/auth/context"
import { ActivityChart } from "@/components/charts/ActivityChart"
import { SeverityBreakdown } from "@/components/charts/SeverityBreakdown"
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { cx } from "@/lib/cx"
import { formatNumber, formatRelative } from "@/lib/format"
import { SetupBanner } from "@/pages/onboarding/SetupBanner"

const RECENT_EVENT_SAMPLE = 500

function Metric({
  label,
  value,
  detail,
  icon: Icon,
  tone = "text-accent",
  to,
}: {
  label: string
  value: ReactNode
  detail?: ReactNode
  icon: LucideIcon
  tone?: string
  to: string
}) {
  return (
    <Link
      to={to}
      className="group rounded-xl border border-border bg-surface p-5 shadow-card transition-colors hover:border-border-strong"
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted">{label}</span>
        <Icon className={cx("size-4", tone)} aria-hidden />
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-tight tabular-nums">{value}</div>
      {detail && <div className="mt-1 text-xs text-subtle">{detail}</div>}
    </Link>
  )
}

function HealthRow({ label, ok, detail }: { label: string; ok: boolean | undefined; detail: string }) {
  return (
    <li className="flex items-center gap-3 py-2.5">
      <span
        className={cx("size-2 rounded-full", ok === undefined ? "bg-subtle" : ok ? "bg-success" : "bg-danger")}
        aria-hidden
      />
      <span className="text-sm">{label}</span>
      <span className="ml-auto text-xs text-muted">{detail}</span>
    </li>
  )
}

export function OverviewPage() {
  const user = useUser()
  const summary = useAlertSummary()
  const detection = useDetectionStatus()
  const database = useDatabaseHealth()
  const latest = useLatestAlerts(6)
  const recent = useRecentEvents(RECENT_EVENT_SAMPLE)

  const byStatus = summary.data?.by_status ?? {}
  const openBySeverity = summary.data?.open_by_severity ?? {}
  const open = (byStatus.open ?? 0) + (byStatus.in_progress ?? 0)
  const urgent = (openBySeverity.critical ?? 0) + (openBySeverity.high ?? 0)

  // Counted relative to when the events were fetched, so renders stay pure.
  const fetchedAt = recent.dataUpdatedAt
  const dayAgo = fetchedAt - 24 * 3600_000
  const eventTimes = (recent.data ?? []).map((event) => event.timestamp)
  const eventsToday = eventTimes.filter((time) => new Date(time).getTime() >= dayAgo).length
  const sampleFull = (recent.data?.length ?? 0) >= RECENT_EVENT_SAMPLE

  const engine = detection.data?.core_engine

  return (
    <>
      <PageHeader
        title={`Welcome back${user.firstName ? `, ${user.firstName}` : ""}`}
        description="What needs attention now, and whether detection is running."
      />
      <SetupBanner />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Open alerts"
          icon={ShieldAlert}
          tone="text-warning"
          to="/alerts?status=open"
          value={summary.data ? formatNumber(open) : "—"}
          detail={summary.data ? `${formatNumber(byStatus.in_progress ?? 0)} under investigation` : " "}
        />
        <Metric
          label="Critical and high"
          icon={ShieldAlert}
          tone="text-critical"
          to="/alerts?severity=critical"
          value={summary.data ? formatNumber(urgent) : "—"}
          detail="Open alerts at the top two severities"
        />
        <Metric
          label="Events, last 24 hours"
          icon={Radar}
          to="/events"
          value={recent.data ? `${formatNumber(eventsToday)}${sampleFull && eventsToday >= RECENT_EVENT_SAMPLE ? "+" : ""}` : "—"}
          detail="By event time"
        />
        <Metric
          label="Detection rules enabled"
          icon={Server}
          tone="text-success"
          to="/rules?status=enabled"
          value={detection.data ? formatNumber(detection.data.enabled_rules) : "—"}
          detail={
            detection.data
              ? `${formatNumber(detection.data.testing_rules)} testing · ${formatNumber(detection.data.total_rules)} in total`
              : " "
          }
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card title="Event activity" description="Events per hour over the last 24 hours" className="xl:col-span-2">
          {recent.isError ? (
            <ErrorState error={recent.error} onRetry={() => void recent.refetch()} />
          ) : (
            <ActivityChart timestamps={eventTimes} now={fetchedAt} />
          )}
        </Card>
        <Card title="Open alerts by severity" description="Open or under investigation">
          {summary.isError ? (
            <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
          ) : (
            <SeverityBreakdown counts={openBySeverity} />
          )}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card
          title="Latest alerts"
          className="xl:col-span-2"
          bodyClassName="p-0"
          actions={
            <Link to="/alerts" className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">
              All alerts <ArrowRight className="size-3.5" aria-hidden />
            </Link>
          }
        >
          {latest.isPending ? (
            <SkeletonRows rows={4} columns={3} />
          ) : latest.isError ? (
            <ErrorState error={latest.error} onRetry={() => void latest.refetch()} />
          ) : latest.data.length === 0 ? (
            <EmptyState title="No alerts yet">
              Alerts appear here when the core engine detects a threat in an event, or when one is raised by another
              source.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {latest.data.map((alert) => (
                <li key={alert.id}>
                  <Link to={`/alerts/${alert.id}`} className="flex items-center gap-4 px-5 py-3 hover:bg-surface-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{alert.title}</span>
                      <span className="block truncate text-xs text-subtle">
                        {alert.source} · {formatRelative(alert.created_at)}
                      </span>
                    </span>
                    <StatusBadge status={alert.status} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Pipeline health" description="Refreshed every 30 seconds">
          <ul className="divide-y divide-border">
            <HealthRow label="API gateway" ok={detection.isError ? false : detection.data ? true : undefined} detail={detection.isError ? "Unreachable" : "Responding"} />
            <HealthRow
              label="Database"
              ok={database.data ? database.data.status === "ok" : database.isError ? false : undefined}
              detail={database.data?.database === "connected" ? "Connected" : database.data ? "Disconnected" : "—"}
            />
            <HealthRow
              label="Core engine"
              ok={engine ? engine.configured && engine.reachable : undefined}
              detail={!engine ? "—" : !engine.configured ? "Not configured" : engine.reachable ? "Reachable" : "Unreachable"}
            />
          </ul>
          {engine && !engine.configured && (
            <p className="mt-3 flex gap-2 text-xs text-muted">
              <Database className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              Events are stored but not analysed. Set CORE_ENGINE_URL on the gateway to turn on detection.
            </p>
          )}
        </Card>
      </div>
    </>
  )
}
