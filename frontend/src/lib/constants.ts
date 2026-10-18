export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export type Severity = (typeof SEVERITIES)[number]

export const ALERT_STATUSES = ["open", "in_progress", "resolved", "closed", "false_positive"] as const
export type AlertStatus = (typeof ALERT_STATUSES)[number]

/** Alerts that still need someone's attention. */
export const ACTIVE_ALERT_STATUSES: readonly AlertStatus[] = ["open", "in_progress"]

export const RULE_STATUSES = ["enabled", "testing", "disabled"] as const
export const RULE_TYPES = ["signature", "anomaly", "behavior", "correlation"] as const
export const DETECTION_SOURCES = ["network", "endpoint", "log", "cloud", "identity"] as const

export const ASSET_TYPES = ["server", "workstation", "laptop", "network_device", "mobile", "cloud", "iot"] as const
export const CASE_STATUSES = ["open", "investigating", "contained", "resolved", "false_positive", "closed"] as const
export type CaseStatus = (typeof CASE_STATUSES)[number]

export const ASSET_STATUSES = ["active", "inactive", "decommissioned"] as const
export const CRITICALITIES = ["critical", "high", "medium", "low"] as const

export const SIMULATION_SCENARIOS = [
  "ransomware",
  "data-exfiltration",
  "lateral-movement",
  "credential-access",
  "phishing",
] as const
export const SIMULATION_SCOPES = ["network", "endpoint", "user"] as const
export const SIMULATION_INTENSITIES = ["low", "medium", "high"] as const

export const EVENT_TYPES = ["process", "network", "authentication", "file", "registry", "dns"] as const

export const PAGE_SIZE = 25

/** How often lists that change on their own (alerts, events, status) are refreshed. */
export const POLL_INTERVAL_MS = 15_000

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value)
}

export function severityRank(value: string | null | undefined): number {
  const index = SEVERITIES.indexOf((value ?? "info") as Severity)
  return index === -1 ? SEVERITIES.length : index
}
