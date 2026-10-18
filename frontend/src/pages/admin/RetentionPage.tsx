import { useState } from "react"
import { toast } from "sonner"

import { useRetention, useRunRetention, useUpdateRetention } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime } from "@/lib/format"

type Kind = "events" | "alerts" | "cases" | "actions" | "notifications" | "labels"

const KINDS: Array<{ kind: Kind; label: string; hint: string }> = [
  { kind: "events", label: "Events", hint: "Events behind an open alert or case are kept regardless" },
  { kind: "alerts", label: "Closed alerts", hint: "Counted from when they last changed; open alerts are kept" },
  { kind: "cases", label: "Closed cases", hint: "Counted from when they last changed; open cases are kept" },
  { kind: "actions", label: "Response actions", hint: "Actions waiting for a decision are kept" },
  { kind: "notifications", label: "Email log", hint: "Which emails were sent, and why some were not" },
  { kind: "labels", label: "Verdicts for retraining", hint: "Your verdicts on alerts, used to improve detection" },
]

function Form({ days, max }: { days: Record<Kind, number>; max: number }) {
  const update = useUpdateRetention()
  const [values, setValues] = useState<Record<Kind, string>>(() => Object.fromEntries(KINDS.map(({ kind }) => [kind, String(days[kind])])) as Record<Kind, string>)

  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault()
        const changed = Object.fromEntries(KINDS.filter(({ kind }) => Number(values[kind]) !== days[kind]).map(({ kind }) => [kind, Number(values[kind])]))
        update.mutate(changed, { onSuccess: () => toast.success("Retention saved"), onError: (error) => toast.error(error.message) })
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {KINDS.map(({ kind, label, hint }) => (
          <Field key={kind} label={`${label} (days)`} hint={hint}>
            {(id, describedBy) => (
              <Input
                id={id}
                aria-describedby={describedBy}
                type="number"
                min={1}
                max={max}
                required
                value={values[kind]}
                onChange={(event) => setValues({ ...values, [kind]: event.target.value })}
              />
            )}
          </Field>
        ))}
      </div>
      <Button type="submit" variant="primary" size="sm" loading={update.isPending}>
        Save
      </Button>
    </form>
  )
}

export function RetentionPage() {
  const retention = useRetention()
  const run = useRunRetention()

  return (
    <>
      <PageHeader
        title="Data retention"
        description="How long your organisation's data is kept. Every hour, what has passed its time is deleted for good. Open cases and alerts, and the events behind them, are always kept. The audit log is kept in full."
      />
      {retention.isPending ? (
        <SkeletonRows rows={4} columns={3} />
      ) : retention.isError ? (
        <ErrorState error={retention.error} onRetry={() => void retention.refetch()} />
      ) : (
        <div className="grid gap-4 xl:grid-cols-3">
          <Card title="How long to keep" description={`Up to ${retention.data.max_days} days on this deployment.`} className="xl:col-span-2">
            <Form days={retention.data.days} max={retention.data.max_days} />
          </Card>
          <Card title="Last clean-up">
            <div className="space-y-3 text-sm">
              {retention.data.last_run ? (
                <>
                  <p>{formatDateTime(retention.data.last_run.at)}</p>
                  <ul className="space-y-1 text-muted">
                    {KINDS.map(({ kind, label }) => (
                      <li key={kind} className="flex justify-between">
                        <span>{label}</span>
                        <span className="tabular-nums">{retention.data.last_run?.deleted[kind] ?? 0} deleted</span>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="text-muted">Not yet.</p>
              )}
              <Button
                size="sm"
                loading={run.isPending}
                onClick={() =>
                  run.mutate(undefined, {
                    onSuccess: (deleted) => toast.success(`Deleted ${Object.values(deleted).reduce((a, b) => a + b, 0)} items`),
                    onError: (error) => toast.error(error.message),
                  })
                }
              >
                Clean up now
              </Button>
            </div>
          </Card>
        </div>
      )}
    </>
  )
}
