import { Link } from "react-router"
import { toast } from "sonner"

import type { Action } from "@/api/client"
import { useDecideAction } from "@/api/queries"
import { Badge, StatusBadge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { formatDateTime, formatRelative } from "@/lib/format"

/** Who asked for an action, in words. */
function requester(action: Action): string {
  if (action.playbook) return `Playbook "${String(action.playbook.name)}"`
  const by = action.requested_by
  return by.type === "api_key" ? `API key ${String(by.name)}` : String(by.name ?? "Someone")
}

/** Actions, with what can be done about each: approve or reject one that waits, undo one that ran. */
export function ActionList({ actions, showCase = false }: { actions: Action[]; showCase?: boolean }) {
  const decide = useDecideAction()
  const act = (action: Action, decision: "approve" | "reject" | "undo") =>
    decide.mutate(
      { actionId: action.id, decision },
      {
        onSuccess: (result) => {
          if (result.status === "failed") toast.error(`${result.label} failed: ${result.error ?? "unknown error"}`)
          else toast.success({ approve: `${action.label}: done`, reject: "Not done", undo: `${action.label}: undone` }[decision])
        },
        onError: (error) => toast.error(error.message),
      },
    )

  return (
    <ul className="divide-y divide-border">
      {actions.map((action) => (
        <li key={action.id} className="flex flex-wrap items-start gap-3 px-4 py-3 text-sm">
          <div className="min-w-0 flex-1 space-y-1">
            <p className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{action.label}</span>
              <span className="truncate text-muted">{action.target.type === "case" ? "this case" : action.target.value}</span>
              <StatusBadge status={action.status} />
              {action.protected && <Badge tone="warning">Protected account</Badge>}
            </p>
            {action.status === "pending" && action.reason && <p className="text-xs text-muted">{action.reason}</p>}
            {action.result?.summary ? <p className="text-xs text-muted">{String(action.result.summary)}</p> : null}
            {action.error && <p className="text-xs text-danger">{action.error}</p>}
            <p className="text-xs text-subtle">
              <span title={formatDateTime(action.created_at)}>{formatRelative(action.created_at)}</span>, {requester(action)}
              {showCase && action.case_id && (
                <>
                  {" · "}
                  <Link to={`/cases/${action.case_id}`} className="hover:text-accent">
                    View case
                  </Link>
                </>
              )}
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            {action.status === "pending" && (
              <>
                <Button size="sm" variant="primary" disabled={decide.isPending} onClick={() => act(action, "approve")}>
                  {action.mode === "notify" ? "Do it" : "Approve"}
                </Button>
                <Button size="sm" disabled={decide.isPending} onClick={() => act(action, "reject")}>
                  {action.mode === "notify" ? "Dismiss" : "Reject"}
                </Button>
              </>
            )}
            {action.can_undo && (
              <Button size="sm" disabled={decide.isPending} onClick={() => act(action, "undo")}>
                Undo
              </Button>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}
