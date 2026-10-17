import type { DetectionRule } from "@/api/client"
import { Badge } from "@/components/ui/Badge"

/** Whether the core engine runs a rule's logic, with the reason when it cannot. */
export function EngineBadge({ engine }: { engine: DetectionRule["engine"] }) {
  return engine.runs ? (
    <Badge tone="success">Runs</Badge>
  ) : (
    <span title={engine.reason ?? undefined}>
      <Badge tone="neutral">Not run</Badge>
    </span>
  )
}
