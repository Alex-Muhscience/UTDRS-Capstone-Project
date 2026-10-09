const dateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
})
const time = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" })
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
]

function toDate(value: string | Date): Date {
  return value instanceof Date ? value : new Date(value)
}

export function formatDateTime(value: string | Date | null | undefined): string {
  return value ? dateTime.format(toDate(value)) : "—"
}

export function formatTime(value: string | Date): string {
  return time.format(toDate(value))
}

/** "3 minutes ago", "yesterday", "just now". */
export function formatRelative(value: string | Date | null | undefined, now = Date.now()): string {
  if (!value) return "—"
  const seconds = (toDate(value).getTime() - now) / 1000
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit)
  }
  return "just now"
}

const ACRONYMS: Record<string, string> = { ml: "ML", dns: "DNS", ip: "IP", os: "OS", iot: "IoT", smb: "SMB", vpn: "VPN" }

/** "in_progress" -> "In progress", "false_positive" -> "False positive", "ml" -> "ML". */
export function humanize(value: string | null | undefined): string {
  if (!value) return "—"
  const words = value
    .replace(/[_-]+/g, " ")
    .trim()
    .split(/\s+/)
    .map((word) => ACRONYMS[word.toLowerCase()] ?? word)
    .join(" ")
  return words.charAt(0).toUpperCase() + words.slice(1)
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}
