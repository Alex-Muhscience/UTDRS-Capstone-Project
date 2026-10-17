import { ExternalLink, UserRoundCheck } from "lucide-react"
import { useState } from "react"
import { Link, useParams } from "react-router"
import { toast } from "sonner"

import type { Alert } from "@/api/client"
import { analysisOf, displayName, useAlert, useAlertTag, useAssignAlert, useEventsById, useUpdateAlertStatus, useUsers } from "@/api/queries"
import { useUser } from "@/auth/context"
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge"
import { BackLink } from "@/components/ui/BackLink"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Field, Select, Textarea } from "@/components/ui/Field"
import { JsonBlock } from "@/components/ui/JsonBlock"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { TagEditor } from "@/components/ui/TagEditor"
import type { AlertStatus } from "@/lib/constants"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"

type Transition = { status: AlertStatus; label: string; primary?: boolean }

/** The next steps offered for an alert in each status. */
const TRANSITIONS: Record<string, Transition[]> = {
  open: [
    { status: "in_progress", label: "Start investigating", primary: true },
    { status: "resolved", label: "Resolve" },
    { status: "false_positive", label: "Mark false positive" },
  ],
  in_progress: [
    { status: "resolved", label: "Resolve", primary: true },
    { status: "false_positive", label: "Mark false positive" },
    { status: "closed", label: "Close" },
  ],
  resolved: [
    { status: "closed", label: "Close", primary: true },
    { status: "open", label: "Reopen" },
  ],
  false_positive: [
    { status: "closed", label: "Close", primary: true },
    { status: "open", label: "Reopen" },
  ],
  closed: [{ status: "open", label: "Reopen" }],
}

type EngineDetails = {
  mitre_techniques?: string[]
  tags?: string[]
  // The rule that matched; rule_source is "gateway" for rules from this catalogue.
  detection?: { rule_source?: string; rule_source_id?: string | null; name?: string }
  [key: string]: unknown
}

function engineMetadata(alert: Alert) {
  const metadata = alert.metadata as { detection_type?: string; core_engine_alert_id?: string; details?: EngineDetails }
  return metadata.details || metadata.detection_type ? metadata : null
}

/** A link to the catalogue rule that raised the alert, when it was one of ours. */
function ruleLink(details: EngineDetails | undefined) {
  const detection = details?.detection
  if (detection?.rule_source !== "gateway" || !detection.rule_source_id) return null
  return (
    <Link to={`/rules/${detection.rule_source_id}`} className="text-accent hover:underline">
      {detection.name ?? "View rule"}
    </Link>
  )
}

function mitreUrl(technique: string) {
  // T1059.001 -> techniques/T1059/001
  return `https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`
}

function Triage({ alert }: { alert: Alert }) {
  const user = useUser()
  const [note, setNote] = useState("")
  const updateStatus = useUpdateAlertStatus(alert.id)
  const assign = useAssignAlert(alert.id)
  const users = useUsers()
  const transitions = TRANSITIONS[alert.status] ?? []
  const people = (users.data ?? []).filter((person) => person.active)
  const assignee = users.data?.find((person) => person.id === alert.assigned_to)

  function assignTo(userId: string, label: string) {
    assign.mutate(userId, {
      onSuccess: () => toast.success(`Alert assigned to ${label}`),
      onError: (error) => toast.error(error.message),
    })
  }

  function move(status: AlertStatus) {
    updateStatus.mutate(
      { status, notes: note.trim() },
      {
        onSuccess: () => {
          toast.success(`Alert ${humanize(status).toLowerCase()}`)
          setNote("")
        },
        onError: (error) => toast.error(error.message),
      },
    )
  }

  return (
    <Card title="Triage" description="Move the alert forward; a note is saved with the status change.">
      <div className="space-y-4">
        <Field label="Note">
          {(id) => (
            <Textarea
              id={id}
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="What did you find? (optional)"
              className="min-h-20"
            />
          )}
        </Field>
        <div className="flex flex-wrap gap-2">
          {transitions.map((transition) => (
            <Button
              key={transition.status}
              variant={transition.primary ? "primary" : "secondary"}
              size="sm"
              loading={updateStatus.isPending && updateStatus.variables?.status === transition.status}
              disabled={updateStatus.isPending}
              onClick={() => move(transition.status)}
            >
              {transition.label}
            </Button>
          ))}
        </div>
        <div className="space-y-3 border-t border-border pt-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm text-muted">
              {alert.assigned_to === user.id
                ? "Assigned to you"
                : alert.assigned_to
                  ? `Assigned to ${assignee ? displayName(assignee) : "a former user"}`
                  : "Unassigned"}
            </span>
            {alert.assigned_to !== user.id && (
              <Button size="sm" loading={assign.isPending} onClick={() => assignTo(user.id, "you")}>
                <UserRoundCheck className="size-3.5" aria-hidden /> Assign to me
              </Button>
            )}
          </div>
          {people.length > 1 && (
            <Select
              aria-label="Assign to someone else"
              value=""
              disabled={assign.isPending}
              placeholder="Assign to someone else…"
              options={people
                .filter((person) => person.id !== alert.assigned_to)
                .map((person) => ({ value: person.id, label: displayName(person) }))}
              onChange={(event) => {
                const person = people.find((candidate) => candidate.id === event.target.value)
                if (person) assignTo(person.id, displayName(person))
              }}
              className="h-8 text-xs"
            />
          )}
        </div>
      </div>
    </Card>
  )
}

function LinkedEvents({ eventIds }: { eventIds: string[] }) {
  const events = useEventsById(eventIds)
  if (eventIds.length === 0) {
    return <EmptyState title="No linked events">This alert was not raised from a stored event.</EmptyState>
  }
  if (events.isPending) return <SkeletonRows rows={eventIds.length} columns={3} />
  if (events.isError) return <ErrorState error={events.error} onRetry={() => void events.refetch()} />
  return (
    <ul className="divide-y divide-border">
      {events.data.map((event) => (
        <li key={event.id}>
          <Link to={`/events/${event.id}`} className="flex items-center gap-4 px-5 py-3 hover:bg-surface-2">
            <Badge>{humanize(event.event_type)}</Badge>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm">{event.description}</span>
              <span className="block text-xs text-subtle">
                {event.source} · {formatDateTime(event.timestamp)}
              </span>
            </span>
            {analysisOf(event)?.status === "threat" && <Badge tone="danger">Threat</Badge>}
          </Link>
        </li>
      ))}
    </ul>
  )
}

export function AlertDetailPage() {
  const { alertId = "" } = useParams()
  const alert = useAlert(alertId)
  const tag = useAlertTag(alertId)

  if (alert.isPending) return <SkeletonRows rows={6} columns={2} />
  if (alert.isError) {
    return (
      <>
        <BackLink to="/alerts">All alerts</BackLink>
        <ErrorState error={alert.error} onRetry={() => void alert.refetch()} />
      </>
    )
  }

  const data = alert.data
  const engine = engineMetadata(data)
  const { mitre_techniques: techniques = [], tags: _engineTags, ...otherDetails } = engine?.details ?? {}

  return (
    <>
      <PageHeader
        eyebrow={<BackLink to="/alerts">All alerts</BackLink>}
        title={data.title}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <StatusBadge status={data.status} />
            <span className="text-subtle">
              Raised {formatRelative(data.created_at)} by {data.source}
            </span>
          </span>
        }
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="What happened">
            <p className="text-sm leading-relaxed whitespace-pre-line">{data.description || "No description."}</p>
            {data.notes && (
              <div className="mt-4 rounded-lg border border-border bg-surface-2 p-3">
                <p className="text-xs font-medium text-subtle">Latest note</p>
                <p className="mt-1 text-sm whitespace-pre-line">{data.notes}</p>
              </div>
            )}
          </Card>

          {engine && (
            <Card title="Detection" description="How the core engine reached this verdict">
              <div className="space-y-5">
                <DescriptionList
                  items={[
                    ["Detector", humanize(engine.detection_type)],
                    [
                      "Rule",
                      ruleLink(engine.details) ?? (engine.details?.detection?.name ? `${engine.details.detection.name} (built in)` : null),
                    ],
                    ["Engine alert", engine.core_engine_alert_id ? <code className="font-mono text-xs">{engine.core_engine_alert_id}</code> : null],
                  ]}
                />
                {techniques.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-subtle">MITRE ATT&amp;CK techniques</p>
                    <ul className="mt-2 flex flex-wrap gap-2">
                      {techniques.map((technique) => (
                        <li key={technique}>
                          <a
                            href={mitreUrl(technique)}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-xs hover:border-accent hover:text-accent"
                          >
                            {technique} <ExternalLink className="size-3" aria-hidden />
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {Object.keys(otherDetails).length > 0 && (
                  <details className="group">
                    <summary className="cursor-pointer text-xs font-medium text-muted select-none hover:text-fg">
                      Engine input and output (JSON)
                    </summary>
                    <div className="mt-3">
                      <JsonBlock value={otherDetails} label="Detection details" />
                    </div>
                  </details>
                )}
              </div>
            </Card>
          )}

          <Card title="Linked events" bodyClassName="p-0">
            <LinkedEvents eventIds={data.event_ids} />
          </Card>
        </div>

        <div className="space-y-4">
          <Triage alert={data} />
          <Card title="Details">
            <DescriptionList
              items={[
                ["Type", humanize(data.type)],
                ["Source", data.source],
                ["Raised", formatDateTime(data.created_at)],
                ["Last updated", formatDateTime(data.updated_at)],
              ]}
            />
          </Card>
          <Card title="Tags">
            <TagEditor
              label="Alert tags"
              values={data.tags}
              placeholder="Add a tag"
              busy={tag.isPending}
              onAdd={(value) => tag.mutate({ tag: value }, { onError: (error) => toast.error(error.message) })}
              onRemove={(value) => tag.mutate({ tag: value, remove: true }, { onError: (error) => toast.error(error.message) })}
            />
          </Card>
        </div>
      </div>
    </>
  )
}
