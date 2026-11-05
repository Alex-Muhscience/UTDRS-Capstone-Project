import type { ReactNode } from "react"

import { cx } from "@/lib/cx"
import { humanize } from "@/lib/format"
import { STATUS_TONES, toneForSeverity, type Tone } from "@/lib/tones"

const tones: Record<Tone, string> = {
  neutral: "bg-surface-3 text-muted ring-border",
  accent: "bg-accent/12 text-accent ring-accent/25",
  success: "bg-success/12 text-success ring-success/25",
  warning: "bg-warning/12 text-warning ring-warning/25",
  danger: "bg-danger/12 text-danger ring-danger/25",
  critical: "bg-critical/14 text-critical ring-critical/30",
  high: "bg-high/14 text-high ring-high/30",
  medium: "bg-medium/14 text-medium ring-medium/30",
  low: "bg-low/14 text-low ring-low/30",
  info: "bg-info/14 text-info ring-info/30",
}

const dots: Record<Tone, string> = {
  neutral: "bg-subtle",
  accent: "bg-accent",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-info",
}

export function Badge({ tone = "neutral", dot, children, className }: { tone?: Tone; dot?: boolean; children: ReactNode; className?: string }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        tones[tone],
        className,
      )}
    >
      {dot && <span className={cx("size-1.5 rounded-full", dots[tone])} aria-hidden />}
      {children}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  return (
    <Badge tone={toneForSeverity(severity)} dot>
      {humanize(severity ?? "unknown")}
    </Badge>
  )
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  return <Badge tone={STATUS_TONES[status ?? ""] ?? "neutral"}>{humanize(status)}</Badge>
}
