import { ShieldCheck, ShieldX } from "lucide-react"
import { useState } from "react"

import type { AuditEntry } from "@/api/client"
import { useAuditLog, useVerifyAuditLog } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Select } from "@/components/ui/Field"
import { JsonBlock } from "@/components/ui/JsonBlock"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

const KINDS = [
  { value: "auth", label: "Sign-ins and accounts" },
  { value: "users", label: "User administration" },
  { value: "api_key", label: "API keys" },
  { value: "rules", label: "Detection rules" },
  { value: "alerts", label: "Alerts" },
  { value: "assets", label: "Assets" },
  { value: "simulations", label: "Simulations" },
]

const OUTCOME_TONES = { success: "success", denied: "warning", failed: "danger" } as const

function actorLabel(actor: AuditEntry["actor"]): string {
  const name = typeof actor.name === "string" ? actor.name : null
  switch (actor.type) {
    case "user":
      return name ?? "A user"
    case "api_key":
      return `API key ${name ?? ""}`.trim()
    case "anonymous":
      return name ? `${name} (not signed in)` : "Not signed in"
    default:
      return humanize(String(actor.type))
  }
}

/** "rules.update_rule_status" -> "Update rule status"; "auth.login_failed" -> "Login failed". */
function actionLabel(action: string): string {
  return humanize(action.split(".").slice(1).join(".") || action)
}

function targetLabel(target: AuditEntry["target"]): string | null {
  if (!target) return null
  return `${humanize(String(target.type))} ${target.name ? String(target.name) : String(target.id ?? "")}`.trim()
}

function ChainCheck() {
  const verify = useVerifyAuditLog()
  const result = verify.data
  return (
    <div className="flex items-center gap-3">
      {result && (
        <span className={`flex items-center gap-1.5 text-sm ${result.ok ? "text-success" : "text-danger"}`} role="status">
          {result.ok ? <ShieldCheck className="size-4" aria-hidden /> : <ShieldX className="size-4" aria-hidden />}
          {result.ok ? `Intact: ${result.checked} entries checked${result.note ? `. ${result.note}` : ""}` : result.problem}
        </span>
      )}
      <Button onClick={() => verify.mutate()} loading={verify.isPending}>
        Verify the log
      </Button>
    </div>
  )
}

export function AuditLogPage() {
  const { filters, page, setFilter, setPage } = useUrlFilters(["kind"] as const)
  const log = useAuditLog({ action: filters.kind, page })
  const [selected, setSelected] = useState<AuditEntry | null>(null)

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Who did what, when and from where: sign-ins, and every change to users, rules, alerts, assets, simulations and API keys. Each entry is chained to the one before, so changes to the log can be detected."
        actions={<ChainCheck />}
      />
      <Card bodyClassName="p-0">
        <div className="flex border-b border-border p-4">
          <Select
            aria-label="Kind of action"
            value={filters.kind}
            onChange={(event) => setFilter("kind", event.target.value)}
            options={KINDS}
            placeholder="Everything"
            className="sm:w-60"
          />
        </div>
        {log.isPending ? (
          <SkeletonRows />
        ) : log.isError ? (
          <ErrorState error={log.error} onRetry={() => void log.refetch()} />
        ) : log.data.rows.length === 0 ? (
          <EmptyState title="Nothing recorded yet">{filters.kind ? "Try another kind of action." : null}</EmptyState>
        ) : (
          <Table label="Audit log">
            <thead>
              <tr>
                <Th className="w-36">When</Th>
                <Th>Who</Th>
                <Th>What</Th>
                <Th className="w-28">Outcome</Th>
                <Th className="w-36">From</Th>
              </tr>
            </thead>
            <tbody>
              {log.data.rows.map((entry) => (
                <Tr key={entry.seq} onClick={() => setSelected(entry)}>
                  <Td className="text-muted" title={formatDateTime(entry.at)}>
                    {formatRelative(entry.at)}
                  </Td>
                  <Td className="max-w-0 truncate">{actorLabel(entry.actor)}</Td>
                  <Td className="max-w-0">
                    <button type="button" className="block truncate text-left font-medium hover:text-accent" onClick={() => setSelected(entry)}>
                      {actionLabel(entry.action)}
                    </button>
                    {targetLabel(entry.target) && <span className="block truncate text-xs text-subtle">{targetLabel(entry.target)}</span>}
                  </Td>
                  <Td>
                    <Badge tone={OUTCOME_TONES[entry.outcome as keyof typeof OUTCOME_TONES] ?? "neutral"}>{humanize(entry.outcome)}</Badge>
                  </Td>
                  <Td className="font-mono text-xs text-muted">{entry.address ?? "—"}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {log.data && <Pagination page={page} hasMore={log.data.hasMore} onPage={setPage} fetching={log.isFetching} />}
      </Card>
      <Dialog
        open={selected !== null}
        onClose={() => setSelected(null)}
        wide
        title={selected ? actionLabel(selected.action) : ""}
        description={selected ? `Entry ${selected.seq}, ${formatDateTime(selected.at)}` : undefined}
        footer={<Button onClick={() => setSelected(null)}>Close</Button>}
      >
        {selected && (
          <div className="space-y-4">
            <DescriptionList
              items={[
                ["Action", <code key="a" className="font-mono text-xs">{selected.action}</code>],
                ["Who", actorLabel(selected.actor)],
                ["Target", targetLabel(selected.target)],
                ["Outcome", humanize(selected.outcome)],
                ["From", selected.address],
                ["Request", selected.request_id ? <code key="r" className="font-mono text-xs">{selected.request_id}</code> : null],
              ]}
            />
            {selected.details && <JsonBlock value={selected.details} label="Details" />}
          </div>
        )}
      </Dialog>
    </>
  )
}
