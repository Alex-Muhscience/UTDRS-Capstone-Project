import { useDetectionStatus } from "@/api/queries"
import { cx } from "@/lib/cx"

/** Whether detection is running: the gateway can reach the core engine. */
export function SystemStatus() {
  const { data, isError } = useDetectionStatus()

  let tone = "bg-subtle"
  let label = "Checking detection…"
  if (isError) {
    tone = "bg-danger"
    label = "Gateway unreachable"
  } else if (data) {
    if (data.status === "active") {
      tone = "bg-success"
      label = "Detection online"
    } else if (data.status === "degraded") {
      tone = "bg-danger"
      label = "Core engine unreachable"
    } else {
      tone = "bg-warning"
      label = "No core engine configured"
    }
  }

  return (
    <span
      className="inline-flex items-center gap-2 rounded-full border border-border bg-surface px-3 py-1 text-xs text-muted"
      role="status"
    >
      <span className="relative flex size-2">
        {data?.status === "active" && (
          <span className={cx("absolute inline-flex size-full animate-ping rounded-full opacity-50", tone)} />
        )}
        <span className={cx("relative inline-flex size-2 rounded-full", tone)} />
      </span>
      {label}
    </span>
  )
}
