import { Clock, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { useDetectionStatus, useReanalyseFailed } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { formatDateTime, formatRelative } from "@/lib/format"

/** Whether the oldest event has waited more than a minute: the engine is behind or unreachable. */
function waitedLong(since: string | null | undefined, now = Date.now()): boolean {
  return Boolean(since) && now - new Date(since as string).getTime() > 60_000
}

/** Events waiting because the core engine is unavailable, and events it could not analyse. */
export function AnalysisQueueNotice() {
  const { data } = useDetectionStatus()
  const isAdmin = useIsAdmin()
  const replay = useReanalyseFailed()
  const queue = data?.analysis
  if (!queue) return null

  const backlog = queue.waiting > 0 && waitedLong(queue.oldest_waiting_since)
  if (!backlog && queue.failed_last_day === 0) return null

  return (
    <div className="mb-4 space-y-2" role="status">
      {backlog && (
        <p className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          <Clock className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
          <span>
            {queue.waiting === 1 ? "1 event is" : `${queue.waiting} events are`} waiting for the core engine, the oldest since{" "}
            <span title={formatDateTime(queue.oldest_waiting_since)}>{formatRelative(queue.oldest_waiting_since)}</span>. They are
            stored, and are analysed as soon as the engine answers again.
          </span>
        </p>
      )}
      {queue.failed_last_day > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          <span className="flex gap-2">
            <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
            <span>
              {queue.failed_last_day === 1 ? "1 event" : `${queue.failed_last_day} events`} could not be analysed in the last
              day.
            </span>
          </span>
          {isAdmin && (
            <Button
              size="sm"
              loading={replay.isPending}
              onClick={() =>
                replay.mutate(undefined, {
                  onSuccess: ({ queued }) => toast.success(queued === 1 ? "1 event queued" : `${queued} events queued`),
                  onError: (error) => toast.error(error.message),
                })
              }
            >
              Analyse them again
            </Button>
          )}
        </div>
      )}
    </div>
  )
}
