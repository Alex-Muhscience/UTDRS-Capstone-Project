import { CircleAlert, Inbox } from "lucide-react"
import type { ReactNode } from "react"

import { ApiError } from "@/api/client"

import { Button } from "./Button"

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-12 text-center">
      <div className="grid size-10 place-items-center rounded-full bg-surface-2 text-subtle">
        <Inbox className="size-5" aria-hidden />
      </div>
      <h3 className="mt-3 text-sm font-semibold">{title}</h3>
      {children && <p className="mt-1 max-w-sm text-sm text-muted">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : "Something went wrong."
  const notFound = error instanceof ApiError && error.status === 404
  return (
    <div role="alert" className="flex flex-col items-center px-6 py-12 text-center">
      <div className="grid size-10 place-items-center rounded-full bg-danger/10 text-danger">
        <CircleAlert className="size-5" aria-hidden />
      </div>
      <h3 className="mt-3 text-sm font-semibold">{notFound ? "Not found" : "Could not load this"}</h3>
      <p className="mt-1 max-w-sm text-sm text-muted">{message}</p>
      {onRetry && !notFound && (
        <Button className="mt-4" size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  )
}

export function SkeletonRows({ rows = 5, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="divide-y divide-border" aria-hidden>
      {Array.from({ length: rows }, (_, row) => (
        <div key={row} className="flex gap-4 px-5 py-3.5">
          {Array.from({ length: columns }, (_, column) => (
            <div
              key={column}
              className="h-3.5 animate-pulse rounded bg-surface-3"
              style={{ width: `${column === 1 ? 32 : 12}%`, opacity: 1 - row * 0.12 }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}
