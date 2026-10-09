import { ArrowRight, CircleCheck, CircleHelp, LoaderCircle, ShieldAlert, TriangleAlert } from "lucide-react"
import type { ReactNode } from "react"
import { Link, useParams } from "react-router"

import type { Event } from "@/api/client"
import { analysisOf, isAwaitingAnalysis, useEvent } from "@/api/queries"
import { Badge, SeverityBadge } from "@/components/ui/Badge"
import { BackLink } from "@/components/ui/BackLink"
import { buttonClasses } from "@/components/ui/buttonClasses"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { JsonBlock } from "@/components/ui/JsonBlock"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { cx } from "@/lib/cx"
import { formatDateTime, humanize } from "@/lib/format"

function Verdict({ tone, icon, title, children }: { tone: string; icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className={cx("flex gap-4 rounded-xl border p-5", tone)} role="status">
      <div className="mt-0.5 shrink-0">{icon}</div>
      <div className="min-w-0 flex-1">
        <h2 className="font-semibold">{title}</h2>
        <div className="mt-1 text-sm text-muted">{children}</div>
      </div>
    </div>
  )
}

function AnalysisPanel({ event }: { event: Event }) {
  const analysis = analysisOf(event)
  if (analysis?.status === "threat") {
    return (
      <Verdict
        tone="border-danger/30 bg-danger/8"
        icon={<ShieldAlert className="size-5 text-danger" aria-hidden />}
        title="Threat detected"
      >
        <p>The core engine flagged this event and raised an alert.</p>
        {analysis.alert_id && (
          <Link to={`/alerts/${analysis.alert_id}`} className={buttonClasses("danger", "sm", "mt-3")}>
            Open the alert <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        )}
      </Verdict>
    )
  }
  if (analysis?.status === "clean") {
    return (
      <Verdict
        tone="border-success/30 bg-success/8"
        icon={<CircleCheck className="size-5 text-success" aria-hidden />}
        title="No threat detected"
      >
        The core engine's rule, anomaly and ML detectors found nothing in this event.
      </Verdict>
    )
  }
  if (analysis?.status === "error") {
    return (
      <Verdict
        tone="border-warning/30 bg-warning/8"
        icon={<TriangleAlert className="size-5 text-warning" aria-hidden />}
        title="Analysis failed"
      >
        The event was stored, but the core engine could not analyse it: {analysis.error ?? "unknown error"}.
      </Verdict>
    )
  }
  if (isAwaitingAnalysis(event)) {
    return (
      <Verdict
        tone="border-accent/30 bg-accent/8"
        icon={<LoaderCircle className="size-5 animate-spin text-accent" aria-hidden />}
        title="Analysing"
      >
        The core engine is analysing this event. This page updates when it has a verdict.
      </Verdict>
    )
  }
  return (
    <Verdict tone="border-border bg-surface" icon={<CircleHelp className="size-5 text-subtle" aria-hidden />} title="Not analysed">
      This event has no verdict. The gateway only sends events for analysis when a core engine is configured
      (CORE_ENGINE_URL).
    </Verdict>
  )
}

export function EventDetailPage() {
  const { eventId = "" } = useParams()
  const event = useEvent(eventId)

  if (event.isPending) return <SkeletonRows rows={6} columns={2} />
  if (event.isError) {
    return (
      <>
        <BackLink to="/events">All events</BackLink>
        <ErrorState error={event.error} onRetry={() => void event.refetch()} />
      </>
    )
  }

  const data = event.data
  return (
    <>
      <PageHeader
        eyebrow={<BackLink to="/events">All events</BackLink>}
        title={data.description}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge>{humanize(data.event_type)}</Badge>
            <span className="text-subtle">
              {data.source} · {formatDateTime(data.timestamp)}
            </span>
          </span>
        }
      />
      <div className="space-y-4">
        <AnalysisPanel event={data} />
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Details">
            <DescriptionList
              items={[
                ["Event time", formatDateTime(data.timestamp)],
                ["Received", formatDateTime(data.created_at)],
                ["Source", data.source],
                ["User", data.user_id],
                ["Source IP", data.source_ip && <code className="font-mono text-xs">{data.source_ip}</code>],
                ["Destination IP", data.destination_ip && <code className="font-mono text-xs">{data.destination_ip}</code>],
                ["Protocol", data.protocol],
                ["Action", data.action],
                ["Asset", data.asset_id && <Link to={`/assets/${data.asset_id}`} className="text-accent hover:underline">{data.asset_id}</Link>],
                ["Severity", data.severity && <SeverityBadge severity={data.severity} />],
              ]}
            />
          </Card>
          <Card title="Raw data" description="As received from the source">
            <JsonBlock value={data.raw_data} label="Raw event data" />
          </Card>
        </div>
      </div>
    </>
  )
}
