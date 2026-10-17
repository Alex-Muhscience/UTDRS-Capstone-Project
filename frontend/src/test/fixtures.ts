import type { Alert, Event, User } from "@/api/client"

const now = "2026-10-09T10:00:00+00:00"

export function fakeToken(expiresInSeconds = 3600): string {
  const payload = btoa(JSON.stringify({ sub: "user-1", exp: Math.floor(Date.now() / 1000) + expiresInSeconds }))
  return `header.${payload.replace(/=+$/, "")}.signature`
}

export const user: User = {
  id: "665f1c2ab1e2c3d4e5f60001",
  username: "ann",
  email: "ann@example.com",
  firstName: "Ann",
  lastName: "Analyst",
  role: "analyst",
  active: true,
  createdAt: now,
  updatedAt: now,
  lastLogin: now,
  preferences: {},
}

export const admin: User = {
  ...user,
  id: "665f1c2ab1e2c3d4e5f60002",
  username: "root",
  email: "root@example.com",
  firstName: "Ada",
  lastName: "Admin",
  role: "admin",
}

export const colleague: User = {
  ...user,
  id: "665f1c2ab1e2c3d4e5f60003",
  username: "ben",
  email: "ben@example.com",
  firstName: "Ben",
  lastName: "Okoth",
}

export function alert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: "665f1c2ab1e2c3d4e5f60101",
    title: "Potential Ransomware Activity: Recovery Inhibited",
    description: "Shadow copies or backups are being deleted",
    severity: "critical",
    source: "core-engine",
    type: "ml",
    status: "open",
    tags: ["ransomware"],
    asset_ids: [],
    event_ids: ["665f1c2ab1e2c3d4e5f60201"],
    created_at: now,
    updated_at: now,
    created_by: null,
    assigned_to: null,
    notes: null,
    metadata: { detection_type: "ml", details: { mitre_techniques: ["T1490"], tags: ["ransomware"] } },
    ...overrides,
  }
}

export function event(overrides: Partial<Event> = {}): Event {
  return {
    id: "665f1c2ab1e2c3d4e5f60201",
    timestamp: now,
    event_type: "process",
    source: "endpoint_agent",
    source_ip: null,
    destination_ip: null,
    protocol: null,
    action: null,
    user_id: "jsmith",
    asset_id: null,
    description: "Shadow copies deleted",
    raw_data: { process_name: "vssadmin.exe", command_line: "vssadmin delete shadows /all /quiet" },
    created_at: now,
    updated_at: now,
    tags: [],
    severity: null,
    metadata: {},
    ...overrides,
  }
}

/** Routes every signed-in page needs (the shell polls these). */
export const tenant = {
  id: "665f1c2ab1e2c3d4e5f60900",
  name: "Acme Clinic",
  slug: "acme-clinic",
  status: "active",
  created_at: now,
  updated_at: now,
}

export function shellRoutes(me: User = user) {
  return {
    "GET /api/v1/auth/me": me,
    "GET /api/v1/auth/config": { allow_registration: true, registration_mode: "join" },
    "GET /api/v1/tenants/current": tenant,
    "GET /api/v1/users/": [user, admin, colleague],
    "GET /api/v1/alerts/summary": { total: 1, by_status: { open: 1 }, open_by_severity: { critical: 1 } },
    "GET /api/v1/detection/": {
      status: "active",
      total_rules: 13,
      enabled_rules: 13,
      disabled_rules: 0,
      testing_rules: 0,
      core_engine: { configured: true, reachable: true },
      rule_sync: { attempted_at: now, ok: true, error: null, rules_sent: 1, succeeded_at: now },
      last_updated: now,
    },
  }
}
