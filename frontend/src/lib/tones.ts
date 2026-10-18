/** Colour tones for badges, by severity and by status. */
export type Tone =
  | "neutral"
  | "accent"
  | "success"
  | "warning"
  | "danger"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"

export function toneForSeverity(severity: string | null | undefined): Tone {
  switch (severity) {
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "info":
      return severity
    default:
      return "neutral"
  }
}

export const STATUS_TONES: Record<string, Tone> = {
  // Alerts
  open: "warning",
  in_progress: "accent",
  resolved: "success",
  closed: "neutral",
  false_positive: "neutral",
  // Cases (open, resolved, closed and false_positive as for alerts)
  investigating: "accent",
  contained: "accent",
  // Detection rules
  enabled: "success",
  testing: "warning",
  disabled: "neutral",
  // Assets
  active: "success",
  inactive: "neutral",
  decommissioned: "neutral",
  // Simulations
  idle: "neutral",
  running: "accent",
  completed: "success",
  failed: "danger",
  // Response actions (running and failed as above)
  pending: "warning",
  succeeded: "success",
  rejected: "neutral",
  undoing: "accent",
  undone: "neutral",
}
