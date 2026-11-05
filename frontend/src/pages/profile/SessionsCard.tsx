import { Monitor } from "lucide-react"
import { toast } from "sonner"

import { useEndOtherSessions, useEndSession, useMySessions } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { formatDateTime, formatRelative } from "@/lib/format"

/** Where you are signed in, and signing out of the places you should not be. */
export function SessionsCard() {
  const sessions = useMySessions()
  const end = useEndSession()
  const endOthers = useEndOtherSessions()
  const others = (sessions.data ?? []).filter((session) => !session.current)

  return (
    <Card title="Sessions" description="Where you are signed in. Sign out of any device you do not recognise, then change your password.">
      {sessions.isError ? (
        <p className="text-sm text-danger">{sessions.error.message}</p>
      ) : !sessions.data ? (
        <p className="text-sm text-muted">Loading…</p>
      ) : (
        <>
          <ul className="divide-y divide-border">
            {sessions.data.map((session) => (
              <li key={session.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                <span className="flex min-w-0 items-start gap-2.5">
                  <Monitor className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
                  <span className="min-w-0">
                    <span className="flex flex-wrap items-center gap-2 font-medium">
                      {session.device}
                      {session.current && <Badge tone="accent">This session</Badge>}
                    </span>
                    <span className="block truncate text-xs text-muted" title={`Signed in ${formatDateTime(session.created_at)}`}>
                      {[session.address, `active ${formatRelative(session.last_used_at)}`].filter(Boolean).join(" · ")}
                    </span>
                  </span>
                </span>
                {!session.current && (
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Sign out ${session.device}`}
                    disabled={end.isPending}
                    onClick={() =>
                      end.mutate(session.id, {
                        onSuccess: () => toast.success(`Signed out ${session.device}`),
                        onError: (error) => toast.error(error.message),
                      })
                    }
                  >
                    Sign out
                  </Button>
                )}
              </li>
            ))}
          </ul>
          {others.length > 0 && (
            <Button
              size="sm"
              className="mt-3"
              loading={endOthers.isPending}
              onClick={() =>
                endOthers.mutate(undefined, {
                  onSuccess: ({ ended }) => toast.success(ended === 1 ? "Signed out 1 other session" : `Signed out ${ended} other sessions`),
                  onError: (error) => toast.error(error.message),
                })
              }
            >
              Sign out everywhere else
            </Button>
          )}
        </>
      )}
    </Card>
  )
}
