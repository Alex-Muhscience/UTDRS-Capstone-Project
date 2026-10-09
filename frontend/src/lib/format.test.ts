import { describe, expect, it } from "vitest"

import { formatRelative, humanize } from "./format"

describe("humanize", () => {
  it("turns API values into labels", () => {
    expect(humanize("in_progress")).toBe("In progress")
    expect(humanize("false_positive")).toBe("False positive")
    expect(humanize("data-exfiltration")).toBe("Data exfiltration")
    expect(humanize("ml")).toBe("ML")
    expect(humanize("network_device")).toBe("Network device")
    expect(humanize("dns")).toBe("DNS")
    expect(humanize(null)).toBe("—")
  })
})

describe("formatRelative", () => {
  const now = Date.parse("2026-10-09T12:00:00Z")

  it("describes recent times", () => {
    expect(formatRelative("2026-10-09T11:59:40Z", now)).toBe("just now")
    expect(formatRelative("2026-10-09T11:55:00Z", now)).toMatch(/5 minutes ago/)
    expect(formatRelative("2026-10-09T09:00:00Z", now)).toMatch(/3 hours ago/)
  })

  it("handles missing values", () => {
    expect(formatRelative(null, now)).toBe("—")
  })
})
