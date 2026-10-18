import { Download, RefreshCw } from "lucide-react"
import { Link, useParams } from "react-router"
import { toast } from "sonner"

import type { Report } from "@/api/client"
import { useDownloadReport, useMakeReport, useReport } from "@/api/queries"
import { Badge, SeverityBadge } from "@/components/ui/Badge"
import { BackLink } from "@/components/ui/BackLink"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime } from "@/lib/format"

const FIGURES: Array<{ key: string; label: string; format: (value: number) => string }> = [
  { key: "alerts", label: "Alerts raised", format: String },
  { key: "cases_opened", label: "Cases opened", format: String },
  { key: "critical_cases", label: "Critical cases", format: String },
  { key: "cases_closed", label: "Cases dealt with", format: String },
  { key: "actions_taken", label: "Response actions", format: String },
  { key: "median_hours_to_resolve", label: "Typical hours to deal with a case", format: (value) => value.toFixed(1) },
  { key: "within_deadline_percent", label: "Within deadline", format: (value) => `${value}%` },
]

function change(value: number | null | undefined, previous: number | null | undefined): string | null {
  if (value == null || previous == null) return null
  if (previous === 0) return value ? "new this month" : "no change"
  const percent = Math.round((100 * (value - previous)) / previous)
  return percent === 0 ? "no change" : `${percent > 0 ? "+" : ""}${percent}% on the month before`
}

function Weekly({ weeks }: { weeks: Report["data"]["weekly_alerts"] }) {
  const max = Math.max(1, ...weeks.map((week) => week.count))
  return (
    <div className="flex h-36 items-end gap-3" role="img" aria-label={`Alerts each week: ${weeks.map((week) => week.count).join(", ")}`}>
      {weeks.map((week) => (
        <div key={week.start} className="flex h-full flex-1 flex-col items-center justify-end gap-1">
          <span className="text-xs tabular-nums text-muted">{week.count}</span>
          <div className="w-full rounded-t bg-accent/80" style={{ height: `${(week.count / max) * 100}%`, minHeight: week.count ? 4 : 0 }} />
          <span className="text-[11px] text-subtle">{new Date(week.start).toLocaleDateString(undefined, { day: "numeric", month: "short", timeZone: "UTC" })}</span>
        </div>
      ))}
    </div>
  )
}

export function ReportPage() {
  const { reportId = "" } = useParams()
  const report = useReport(reportId)
  const download = useDownloadReport()
  const remake = useMakeReport()

  if (report.isPending) return <SkeletonRows rows={6} columns={2} />
  if (report.isError) {
    return (
      <>
        <BackLink to="/reports">All reports</BackLink>
        <ErrorState error={report.error} onRetry={() => void report.refetch()} />
      </>
    )
  }

  const { data } = report.data
  return (
    <>
      <PageHeader
        eyebrow={<BackLink to="/reports">All reports</BackLink>}
        title={`Security report: ${data.title}`}
        description={`${data.organisation} · made ${formatDateTime(report.data.generated_at)}`}
        actions={
          <>
            <Button
              size="sm"
              loading={remake.isPending}
              onClick={() => remake.mutate(data.period, { onSuccess: () => toast.success("Report updated"), onError: (error) => toast.error(error.message) })}
            >
              <RefreshCw className="size-4" aria-hidden /> Update
            </Button>
            <Button
              size="sm"
              variant="primary"
              loading={download.isPending}
              onClick={() => download.mutate({ reportId, period: data.period }, { onError: (error) => toast.error(error.message) })}
            >
              <Download className="size-4" aria-hidden /> Download PDF
            </Button>
          </>
        }
      />
      <div className="space-y-4">
        <Card>
          <div className="space-y-2 text-sm">
            {data.headline.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
        </Card>
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="What to do next">
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {data.recommendations.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </Card>
          <Card title="Alerts each week">
            <Weekly weeks={data.weekly_alerts} />
          </Card>
        </div>
        <Card title="The month in figures">
          <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FIGURES.map(({ key, label, format }) => {
              const figure = data.figures[key]
              return (
                <div key={key}>
                  <dt className="text-xs text-subtle">{label}</dt>
                  <dd className="text-2xl font-semibold tabular-nums">{figure?.value == null ? "—" : format(figure.value)}</dd>
                  {change(figure?.value, figure?.previous) && <dd className="text-xs text-muted">{change(figure?.value, figure?.previous)}</dd>}
                </div>
              )
            })}
          </dl>
        </Card>
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="What the threats were">
            {data.top_threats.length ? (
              <ul className="space-y-1 text-sm">
                {data.top_threats.map((threat) => (
                  <li key={threat.name} className="flex justify-between gap-3">
                    <span>{threat.name}</span>
                    <span className="tabular-nums text-muted">{threat.count}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No alerts this month.</p>
            )}
          </Card>
          <Card title="Most often involved">
            {data.most_targeted.length ? (
              <ul className="space-y-1 text-sm">
                {data.most_targeted.map((target) => (
                  <li key={`${target.type}:${target.name}`} className="flex justify-between gap-3">
                    <span>
                      {target.name} <span className="text-xs text-subtle">{target.type}</span>
                    </span>
                    <span className="tabular-nums text-muted">
                      {target.cases} case{target.cases === 1 ? "" : "s"}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No users or devices were involved in cases.</p>
            )}
          </Card>
          <Card title="What UTDRS did">
            {data.actions.taken ? (
              <div className="space-y-2 text-sm">
                <p>
                  {data.actions.taken} action{data.actions.taken === 1 ? "" : "s"} taken: {data.actions.automatic} on its own, {data.actions.approved} approved by your
                  people. {data.actions.undone} undone, {data.actions.rejected} turned down, {data.actions.failed} failed.
                </p>
                <ul className="space-y-1">
                  {data.actions.by_action.map((action) => (
                    <li key={action.label} className="flex justify-between gap-3">
                      <span>{action.label}</span>
                      <span className="tabular-nums text-muted">{action.count}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-sm text-muted">No response actions were taken this month.</p>
            )}
          </Card>
          <Card title="Still open" description={`${data.outstanding.open_cases} open, ${data.outstanding.overdue} overdue, ${data.outstanding.awaiting_approval} waiting for approval`}>
            {data.outstanding.top.length ? (
              <ul className="space-y-2 text-sm">
                {data.outstanding.top.map((item) => (
                  <li key={item.id} className="flex items-center gap-2">
                    <SeverityBadge severity={item.priority} />
                    <Link to={`/cases/${item.id}`} className="min-w-0 flex-1 truncate hover:text-accent">
                      {item.title}
                    </Link>
                    {item.overdue && <Badge tone="danger">Overdue</Badge>}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No cases are open.</p>
            )}
          </Card>
        </div>
      </div>
    </>
  )
}
