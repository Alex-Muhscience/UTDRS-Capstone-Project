import { AlertTriangle, Briefcase, CheckCircle2, FileText, Hand, Plug, UserCheck, XCircle } from "lucide-react"
import type { ComponentType } from "react"
import { useNavigate } from "react-router"

import type { InboxItem } from "@/api/client"
import { useMarkRead } from "@/api/queries"
import { cx } from "@/lib/cx"
import { formatDateTime, formatRelative } from "@/lib/format"

const ICONS: Record<string, ComponentType<{ className?: string }>> = {
  alert: AlertTriangle,
  case: Briefcase,
  approval: Hand,
  action_failed: XCircle,
  action_done: CheckCircle2,
  report: FileText,
  connector: Plug,
  alert_assigned: UserCheck,
  case_assigned: UserCheck,
}

const URGENT = new Set(["critical", "high"])

/** One notification: opening it marks it read and goes to what it is about. */
export function InboxItemRow({ item, onOpen, compact }: { item: InboxItem; onOpen?: () => void; compact?: boolean }) {
  const markRead = useMarkRead()
  const navigate = useNavigate()
  const Icon = ICONS[item.kind] ?? AlertTriangle
  return (
    <li>
      <button
        type="button"
        onClick={() => {
          if (!item.read) markRead.mutate([item.id])
          onOpen?.()
          if (item.link) void navigate(item.link)
        }}
        className={cx("flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-surface-2", !item.read && "bg-accent/5")}
      >
        <Icon className={cx("mt-0.5 size-4 shrink-0", URGENT.has(item.severity ?? "") ? "text-danger" : "text-subtle")} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className={cx("block text-sm", compact && "truncate", !item.read && "font-medium")}>{item.title}</span>
          {item.body && !compact && <span className="mt-0.5 block text-xs text-muted">{item.body}</span>}
          <span className="mt-0.5 block text-xs text-subtle" title={formatDateTime(item.created_at)}>
            {formatRelative(item.created_at)}
          </span>
        </span>
        {!item.read && (
          <span className="mt-1.5 size-2 shrink-0 rounded-full bg-accent">
            <span className="sr-only">Unread</span>
          </span>
        )}
      </button>
    </li>
  )
}
