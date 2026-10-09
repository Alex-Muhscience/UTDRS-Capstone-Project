import { Link } from "react-router"

import { SEVERITIES } from "@/lib/constants"
import { cx } from "@/lib/cx"
import { formatNumber, humanize } from "@/lib/format"

const FILLS: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
}

/** A stacked bar of counts by severity, with a linked legend. */
export function SeverityBreakdown({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITIES.reduce((sum, severity) => sum + (counts[severity] ?? 0), 0)

  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        {total > 0 &&
          SEVERITIES.map((severity) => {
            const count = counts[severity] ?? 0
            return count ? (
              <div key={severity} className={FILLS[severity]} style={{ width: `${(count / total) * 100}%` }} />
            ) : null
          })}
      </div>
      <ul className="mt-5 space-y-1">
        {SEVERITIES.map((severity) => {
          const count = counts[severity] ?? 0
          return (
            <li key={severity}>
              <Link
                to={`/alerts?severity=${severity}`}
                className="flex items-center gap-3 rounded-md px-2 py-1.5 text-sm hover:bg-surface-2"
              >
                <span className={cx("size-2 rounded-full", FILLS[severity])} aria-hidden />
                <span className="text-muted">{humanize(severity)}</span>
                <span className={cx("ml-auto font-medium tabular-nums", !count && "text-subtle")}>{formatNumber(count)}</span>
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
