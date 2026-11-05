import type { Event } from "@/api/client"
import { analysisOf, isAwaitingAnalysis, isRetryingAnalysis } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"

/** The core engine's verdict on an event. */
export function AnalysisBadge({ event }: { event: Event }) {
  const status = analysisOf(event)?.status
  if (status === "threat") return <Badge tone="danger" dot>Threat</Badge>
  if (status === "clean") return <Badge tone="success" dot>Clean</Badge>
  if (status === "error") return <Badge tone="warning" dot>Analysis failed</Badge>
  if (isRetryingAnalysis(event)) return <Badge tone="warning" dot>Waiting for engine</Badge>
  if (isAwaitingAnalysis(event)) return <Badge tone="accent" dot>Analysing</Badge>
  return <Badge>Not analysed</Badge>
}
