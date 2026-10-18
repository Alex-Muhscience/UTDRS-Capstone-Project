import { toast } from "sonner"

import type { ActionType, Playbook } from "@/api/client"
import { useActionTypes, usePlaybooks, useUpdatePlaybook } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatRelative, humanize } from "@/lib/format"

const MODES = [
  { value: "approval", label: "Ask before acting" },
  { value: "automatic", label: "Act on its own" },
  { value: "notify", label: "Only suggest" },
]

const TARGETS: Record<string, string> = { user: "each user involved", message: "the email", case: "the case" }

/** When the playbook runs, in words. */
function trigger(playbook: Playbook): string {
  const { min_severity, tags, techniques } = playbook.trigger ?? { min_severity: "medium", tags: [], techniques: [] }
  const what = [...(tags ?? []).map(humanize), ...(techniques ?? [])]
  return `${humanize(min_severity)} or worse alerts${what.length ? ` about ${what.join(", ")}` : ""}`
}

function PlaybookCard({ playbook, types }: { playbook: Playbook; types: ActionType[] }) {
  const isAdmin = useIsAdmin()
  const update = useUpdatePlaybook()
  const change = (body: { enabled?: boolean; mode?: Playbook["mode"] }, message: string) =>
    update.mutate({ playbookId: playbook.id, ...body }, { onSuccess: () => toast.success(message), onError: (error) => toast.error(error.message) })

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          {playbook.name}
          {playbook.built_in && <Badge>Built in</Badge>}
          {!playbook.enabled && <Badge>Off</Badge>}
        </span>
      }
      description={playbook.description}
      actions={
        isAdmin ? (
          <Button size="sm" disabled={update.isPending} onClick={() => change({ enabled: !playbook.enabled }, playbook.enabled ? "Playbook turned off" : "Playbook turned on")}>
            {playbook.enabled ? "Turn off" : "Turn on"}
          </Button>
        ) : undefined
      }
    >
      <div className="space-y-3 text-sm">
        <p>
          <span className="text-subtle">Runs for </span>
          {trigger(playbook)}
        </p>
        <ol className="list-decimal space-y-1 pl-5">
          {playbook.steps.map((step, index) => {
            const type = types.find((t) => t.name === step.action)
            return (
              <li key={`${step.action}-${index}`}>
                {type?.label ?? step.action}, for {TARGETS[step.target] ?? step.target}
                {type && !type.connected && <span className="text-xs text-warning"> — needs {type.connector_name}, which is not connected</span>}
              </li>
            )
          })}
        </ol>
        <div className="flex flex-wrap items-center gap-3">
          {isAdmin ? (
            <label className="flex items-center gap-2 text-xs text-muted">
              Mode
              <Select
                className="w-auto"
                value={playbook.mode}
                options={MODES}
                disabled={update.isPending}
                onChange={(event) => change({ mode: event.target.value as Playbook["mode"] }, "Mode changed")}
              />
            </label>
          ) : (
            <Badge>{MODES.find((m) => m.value === playbook.mode)?.label}</Badge>
          )}
          <span className="text-xs text-subtle">{playbook.last_run_at ? `Last ran ${formatRelative(playbook.last_run_at)}` : "Has not run yet"}</span>
        </div>
      </div>
    </Card>
  )
}

export function PlaybooksPage() {
  const playbooks = usePlaybooks()
  const types = useActionTypes()

  return (
    <>
      <PageHeader
        title="Playbooks"
        description="What UTDRS does when it finds a kind of threat. Each runs once per case; what it may do on its own is capped by the safety limits on the Response page."
      />
      {playbooks.isPending ? (
        <SkeletonRows rows={4} columns={2} />
      ) : playbooks.isError ? (
        <ErrorState error={playbooks.error} onRetry={() => void playbooks.refetch()} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {playbooks.data.map((playbook) => (
            <PlaybookCard key={playbook.id} playbook={playbook} types={types.data ?? []} />
          ))}
        </div>
      )}
    </>
  )
}
