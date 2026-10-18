import { Plus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { useDeleteSuppression, useDetectorQuality, useSuppressions, useUpdateSuppression } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative } from "@/lib/format"

import { SuppressionDialog } from "./SuppressionDialog"

/** Entity types in words. */
const ENTITY_WORDS: Record<string, string> = { user: "user", host: "device", asset: "device", ip: "address", sender: "sender", file_hash: "file", message: "email" }

function Quality() {
  const quality = useDetectorQuality()
  if (quality.isPending) return <SkeletonRows rows={3} />
  if (quality.isError) return <ErrorState error={quality.error} onRetry={() => void quality.refetch()} />
  if (!quality.data.length) return <EmptyState title="No alerts in the last 30 days" />
  return (
    <Table label="Detector quality">
      <thead>
        <tr>
          <Th>Detector</Th>
          <Th className="w-20 text-right">Alerts</Th>
          <Th className="w-28 text-right">Suppressed</Th>
          <Th className="w-48">Verdicts (real / false / expected)</Th>
          <Th className="w-28 text-right">Precision</Th>
        </tr>
      </thead>
      <tbody>
        {quality.data.map((row) => (
          <Tr key={row.detector}>
            <Td className="max-w-0">
              <span className="flex items-center gap-2">
                <span className="truncate font-medium">{row.name}</span>
                {row.noisy && <Badge tone="warning">Noisy</Badge>}
              </span>
            </Td>
            <Td className="text-right tabular-nums">{row.alerts}</Td>
            <Td className="text-right tabular-nums">{row.suppressed}</Td>
            <Td className="tabular-nums">
              {row.true_positive} / {row.false_positive} / {row.benign}
            </Td>
            <Td className="text-right tabular-nums">{row.precision == null ? "—" : `${Math.round(row.precision * 100)}%`}</Td>
          </Tr>
        ))}
      </tbody>
    </Table>
  )
}

function Suppressions() {
  const suppressions = useSuppressions()
  const update = useUpdateSuppression()
  const remove = useDeleteSuppression()
  const [now] = useState(() => Date.now())
  if (suppressions.isPending) return <SkeletonRows rows={3} />
  if (suppressions.isError) return <ErrorState error={suppressions.error} onRetry={() => void suppressions.refetch()} />
  if (!suppressions.data.length) return <EmptyState title="Nothing is suppressed">Mark a noisy alert a false positive or expected activity to suppress alerts like it.</EmptyState>
  return (
    <ul className="divide-y divide-border">
      {suppressions.data.map((item) => {
        const expired = item.expires_at !== null && item.expires_at !== undefined && new Date(item.expires_at).getTime() <= now
        const what = [
          item.title_contains && `title contains "${item.title_contains}"`,
          item.detector && "from the same detector",
          item.entity && `involving ${ENTITY_WORDS[item.entity.type] ?? item.entity.type} ${item.entity.value}`,
          `up to ${item.max_severity}`,
        ].filter(Boolean)
        return (
          <li key={item.id} className="flex flex-wrap items-start gap-3 px-5 py-3 text-sm">
            <div className="min-w-0 flex-1 space-y-1">
              <p className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{item.name}</span>
                {!item.enabled && <Badge>Off</Badge>}
                {expired && <Badge tone="warning">Expired</Badge>}
              </p>
              <p className="text-muted">
                {item.reason}. Alerts {what.join(", ")}.
              </p>
              <p className="text-xs text-subtle">
                {item.hits} suppressed{item.last_hit_at ? `, last ${formatRelative(item.last_hit_at)}` : ""} ·{" "}
                {item.expires_at ? `until ${formatDateTime(item.expires_at)}` : "never expires"} · by {String(item.created_by.name ?? "someone")}
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              <Button size="sm" disabled={update.isPending} onClick={() => update.mutate({ suppressionId: item.id, enabled: !item.enabled }, { onError: (error) => toast.error(error.message) })}>
                {item.enabled ? "Turn off" : "Turn on"}
              </Button>
              <Button size="sm" disabled={remove.isPending} onClick={() => remove.mutate(item.id, { onSuccess: () => toast.success("Suppression deleted"), onError: (error) => toast.error(error.message) })}>
                Delete
              </Button>
            </div>
          </li>
        )
      })}
    </ul>
  )
}

export function TuningPage() {
  const [creating, setCreating] = useState(false)
  return (
    <>
      <PageHeader
        title="Tuning"
        description="Make detection fit your organisation: see which detectors are noisy, and suppress alerts you know are expected. Your verdicts on alerts feed both, and are kept for retraining the models."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="size-4" aria-hidden /> New suppression
          </Button>
        }
      />
      <div className="space-y-4">
        <Card title="Detector quality" description="The last 30 days. A detector is noisy when most of at least five verdicts were not real threats." bodyClassName="p-0">
          <Quality />
        </Card>
        <Card title="Suppressions" bodyClassName="p-0">
          <Suppressions />
        </Card>
      </div>
      {creating && <SuppressionDialog open onClose={() => setCreating(false)} />}
    </>
  )
}
