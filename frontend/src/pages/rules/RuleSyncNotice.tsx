import { AlertTriangle, Info } from "lucide-react"
import type { ReactNode } from "react"

import { useDetectionStatus } from "@/api/queries"
import { cx } from "@/lib/cx"
import { formatDateTime, formatRelative } from "@/lib/format"

/** Whether the rules in this catalogue are reaching the core engine. */
export function RuleSyncNotice() {
  const { data } = useDetectionStatus()
  if (!data) return null

  const sync = data.rule_sync
  let warning = false
  let message: ReactNode
  if (!data.core_engine.configured) {
    message = "No core engine is configured, so these rules are stored but not run."
  } else if (!sync) {
    message = "These rules have not been sent to the core engine yet; the gateway sends them within a minute of starting."
  } else if (sync.ok) {
    message = (
      <>
        The core engine runs every enabled rule marked <strong className="font-medium text-fg">Runs</strong>, alongside its
        built-in rules and its anomaly and ML detectors. Rules were last sent{" "}
        <span title={formatDateTime(sync.attempted_at)}>{formatRelative(sync.attempted_at)}</span> ({sync.rules_sent}{" "}
        {sync.rules_sent === 1 ? "rule" : "rules"}).
      </>
    )
  } else {
    warning = true
    message = (
      <>
        The rules could not be sent to the core engine{" "}
        <span title={formatDateTime(sync.attempted_at)}>{formatRelative(sync.attempted_at)}</span>: {sync.error}. The gateway
        tries again every minute; until then the engine runs the rules it last received
        {sync.succeeded_at ? <> ({formatRelative(sync.succeeded_at)})</> : null}.
      </>
    )
  }

  const Icon = warning ? AlertTriangle : Info
  return (
    <p
      className={cx(
        "mb-4 flex gap-2 rounded-lg border px-4 py-3 text-sm",
        warning ? "border-warning/40 bg-warning/10 text-fg" : "border-border bg-surface text-muted",
      )}
      role={warning ? "alert" : undefined}
    >
      <Icon className={cx("mt-0.5 size-4 shrink-0", warning ? "text-warning" : "text-accent")} aria-hidden />
      <span>{message}</span>
    </p>
  )
}
