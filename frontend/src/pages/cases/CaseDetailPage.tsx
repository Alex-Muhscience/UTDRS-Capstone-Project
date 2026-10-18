import { useState } from "react"
import { Link, useParams } from "react-router"
import { toast } from "sonner"

import type { Case } from "@/api/client"
import { displayName, useActions, useAddCaseNote, useCase, useCaseEvidence, usePlaybooks, useRunPlaybook, useUpdateCase, useUsers } from "@/api/queries"
import { useUser } from "@/auth/context"
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge"
import { BackLink } from "@/components/ui/BackLink"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Field, Select, Textarea } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { ActionList } from "@/pages/response/ActionList"
import type { CaseStatus } from "@/lib/constants"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"

type Step = { status: CaseStatus; label: string; primary?: boolean }

/** What can be done next with a case in each status. */
const STEPS: Record<string, Step[]> = {
  open: [
    { status: "investigating", label: "Start investigating", primary: true },
    { status: "false_positive", label: "False positive" },
  ],
  investigating: [
    { status: "contained", label: "Contained", primary: true },
    { status: "resolved", label: "Resolve" },
    { status: "false_positive", label: "False positive" },
  ],
  contained: [
    { status: "resolved", label: "Resolve", primary: true },
    { status: "investigating", label: "Back to investigating" },
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

const PRIORITIES = ["critical", "high", "medium", "low", "info"].map((value) => ({ value, label: humanize(value) }))

/** One line of the timeline, in words. */
function describe(entry: Case["timeline"][number], name: (id: string | null | undefined) => string): string {
  const data = entry.data as { before?: string | null; after?: string | null; severity?: string }
  switch (entry.kind) {
    case "created":
      return "Case opened"
    case "alert_added":
      return `Alert: ${entry.text ?? ""}`
    case "status_changed":
      return `Status: ${humanize(data.before ?? "")} → ${humanize(data.after ?? "")}`
    case "priority_changed":
      return `Priority: ${humanize(data.before ?? "")} → ${humanize(data.after ?? "")}`
    case "owner_changed":
      return data.after ? `Assigned to ${name(data.after)}` : "Unassigned"
    case "title_changed":
      return `Renamed to "${data.after ?? ""}"`
    case "note":
    case "action":
    case "playbook":
      return entry.text ?? ""
    default:
      return entry.text ?? humanize(entry.kind)
  }
}

function Workflow({ item }: { item: Case }) {
  const me = useUser()
  const users = useUsers()
  const update = useUpdateCase(item.id)
  const addNote = useAddCaseNote(item.id)
  const [note, setNote] = useState("")
  const people = (users.data ?? []).filter((person) => person.active)

  const change = (body: Parameters<typeof update.mutate>[0], message: string) =>
    update.mutate(body, { onSuccess: () => toast.success(message), onError: (error) => toast.error(error.message) })

  return (
    <Card title="Work the case" description="Closing it, resolving it or marking it a false positive does the same to its open alerts.">
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {(STEPS[item.status] ?? []).map((step) => (
            <Button
              key={step.status}
              size="sm"
              variant={step.primary ? "primary" : "secondary"}
              disabled={update.isPending}
              onClick={() => change({ status: step.status }, `Case ${humanize(step.status).toLowerCase()}`)}
            >
              {step.label}
            </Button>
          ))}
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Owner">
            {(id) => (
              <Select
                id={id}
                value={item.owner_id ?? ""}
                placeholder="Unassigned"
                options={people.map((person) => ({ value: person.id, label: person.id === me.id ? `${displayName(person)} (you)` : displayName(person) }))}
                disabled={update.isPending}
                onChange={(event) => change({ owner_id: event.target.value || null }, event.target.value ? "Owner changed" : "Unassigned")}
              />
            )}
          </Field>
          <Field label="Priority">
            {(id) => (
              <Select
                id={id}
                value={item.priority}
                options={PRIORITIES}
                disabled={update.isPending}
                onChange={(event) => change({ priority: event.target.value as Case["priority"] }, "Priority changed")}
              />
            )}
          </Field>
        </div>
        <form
          className="space-y-2 border-t border-border pt-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (!note.trim()) return
            addNote.mutate(note.trim(), {
              onSuccess: () => {
                setNote("")
                toast.success("Note added")
              },
              onError: (error) => toast.error(error.message),
            })
          }}
        >
          <Field label="Note">
            {(id) => <Textarea id={id} value={note} onChange={(event) => setNote(event.target.value)} placeholder="What did you find, or do?" className="min-h-20" />}
          </Field>
          <Button type="submit" size="sm" loading={addNote.isPending} disabled={!note.trim()}>
            Add note
          </Button>
        </form>
      </div>
    </Card>
  )
}

function Response({ caseId }: { caseId: string }) {
  const actions = useActions({ caseId })
  const playbooks = usePlaybooks()
  const run = useRunPlaybook(caseId)
  const [chosen, setChosen] = useState("")

  return (
    <Card title="Response" description="Actions taken or suggested for this case." bodyClassName="p-0">
      {actions.data?.rows.length ? <ActionList actions={actions.data.rows} /> : <p className="px-5 py-4 text-sm text-muted">No actions yet.</p>}
      <form
        className="flex gap-2 border-t border-border px-5 py-4"
        onSubmit={(event) => {
          event.preventDefault()
          if (!chosen) return
          run.mutate(chosen, {
            onSuccess: (result) => {
              const ran = result.actions.length
              toast.success(`${ran} action${ran === 1 ? "" : "s"}${result.skipped.length ? `, ${result.skipped.length} skipped` : ""}`)
              result.skipped.forEach((reason) => toast.warning(reason))
            },
            onError: (error) => toast.error(error.message),
          })
        }}
      >
        <Select
          aria-label="Playbook"
          value={chosen}
          placeholder="Run a playbook…"
          options={(playbooks.data ?? []).map((playbook) => ({ value: playbook.id, label: playbook.name }))}
          onChange={(event) => setChosen(event.target.value)}
        />
        <Button type="submit" size="sm" loading={run.isPending} disabled={!chosen}>
          Run
        </Button>
      </form>
    </Card>
  )
}

export function CaseDetailPage() {
  const { caseId = "" } = useParams()
  const item = useCase(caseId)
  const evidence = useCaseEvidence(caseId)
  const me = useUser()
  const users = useUsers()
  const name = (id: string | null | undefined) => {
    if (!id) return "nobody"
    if (id === me.id) return "you"
    const person = users.data?.find((candidate) => candidate.id === id)
    return person ? displayName(person) : "a former user"
  }

  if (item.isPending) return <SkeletonRows rows={6} columns={2} />
  if (item.isError) {
    return (
      <>
        <BackLink to="/cases">All cases</BackLink>
        <ErrorState error={item.error} onRetry={() => void item.refetch()} />
      </>
    )
  }

  const data = item.data
  const explanation = data.explanation
  return (
    <>
      <PageHeader
        eyebrow={<BackLink to="/cases">All cases</BackLink>}
        title={data.title}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.priority} />
            <StatusBadge status={data.status} />
            {data.breached && <Badge tone="danger">Overdue</Badge>}
            <span className="text-subtle">
              {data.alert_ids.length} alert{data.alert_ids.length === 1 ? "" : "s"}, last {formatRelative(data.last_seen)}
            </span>
          </span>
        }
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {explanation && (
            <Card title="What is going on">
              <div className="space-y-3 text-sm">
                <p>{explanation.what_happened}</p>
                <p className="text-muted">{explanation.why_it_matters}</p>
                <div>
                  <p className="text-xs font-medium text-subtle">What to do</p>
                  <ol className="mt-1 list-decimal space-y-1 pl-5">
                    {explanation.next_steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                </div>
              </div>
            </Card>
          )}
          <Card title="Alerts" bodyClassName="p-0">
            {evidence.isPending ? (
              <SkeletonRows rows={2} />
            ) : (
              <ul className="divide-y divide-border">
                {(evidence.data?.alerts ?? []).map((alert) => (
                  <li key={String(alert.id)} className="flex items-center gap-3 px-4 py-3 text-sm">
                    <SeverityBadge severity={String(alert.severity)} />
                    <Link to={`/alerts/${String(alert.id)}`} className="min-w-0 flex-1 truncate font-medium hover:text-accent">
                      {String(alert.title)}
                    </Link>
                    <StatusBadge status={String(alert.status)} />
                    <span className="w-24 text-right text-xs text-subtle">{formatRelative(String(alert.created_at))}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Timeline">
            <ol className="space-y-3">
              {[...data.timeline].reverse().map((entry, index) => (
                <li key={`${entry.at}-${index}`} className="flex gap-3 text-sm">
                  <span className="w-28 shrink-0 text-xs text-subtle" title={formatDateTime(entry.at)}>
                    {formatRelative(entry.at)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className={entry.kind === "note" ? "whitespace-pre-line" : undefined}>{describe(entry, name)}</span>
                    {entry.actor?.name ? <span className="block text-xs text-subtle">{String(entry.actor.name)}</span> : null}
                  </span>
                </li>
              ))}
            </ol>
          </Card>
        </div>
        <div className="space-y-4">
          <Workflow item={data} />
          <Response caseId={data.id} />
          <Card title="Details">
            <DescriptionList
              items={[
                ["Owner", data.owner_id ? displayName(users.data?.find((person) => person.id === data.owner_id) ?? { username: "former user" }) : "Unassigned"],
                ["Due", <span key="due" title={formatDateTime(data.due_at)}>{formatDateTime(data.due_at)}</span>],
                ["First seen", formatDateTime(data.first_seen)],
                ["Last seen", formatDateTime(data.last_seen)],
                [
                  "Involves",
                  data.entities.length ? (
                    <span className="flex flex-wrap gap-1">
                      {data.entities.map((entity) => (
                        <Badge key={`${entity.type}:${entity.value}`}>
                          {humanize(entity.type)}: {entity.name ?? entity.value}
                        </Badge>
                      ))}
                    </span>
                  ) : null,
                ],
                [
                  "Techniques",
                  data.techniques.length ? (
                    <span className="flex flex-wrap gap-1">
                      {data.techniques.map((technique) => (
                        <Badge key={technique}>{technique}</Badge>
                      ))}
                    </span>
                  ) : null,
                ],
              ]}
            />
          </Card>
        </div>
      </div>
    </>
  )
}
