import { useParams } from "react-router"

import { useRule } from "@/api/queries"
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge"
import { BackLink } from "@/components/ui/BackLink"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { JsonBlock } from "@/components/ui/JsonBlock"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime, humanize } from "@/lib/format"

import { RuleStatusSelect } from "./RuleStatusSelect"

export function RuleDetailPage() {
  const { ruleId = "" } = useParams()
  const rule = useRule(ruleId)

  if (rule.isPending) return <SkeletonRows rows={6} columns={2} />
  if (rule.isError) {
    return (
      <>
        <BackLink to="/rules">All rules</BackLink>
        <ErrorState error={rule.error} onRetry={() => void rule.refetch()} />
      </>
    )
  }

  const data = rule.data
  const metrics = data.performance_metrics
  return (
    <>
      <PageHeader
        eyebrow={<BackLink to="/rules">All rules</BackLink>}
        title={data.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <StatusBadge status={data.status} />
            <span className="text-subtle">{data.description}</span>
          </span>
        }
        actions={<RuleStatusSelect ruleId={data.id} status={data.status} name={data.name} />}
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Logic">
            <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-4 font-mono text-xs leading-relaxed">
              {data.logic}
            </pre>
          </Card>
          {Object.keys(metrics).length > 0 && (
            <Card title="Performance">
              <JsonBlock value={metrics} label="Performance metrics" />
            </Card>
          )}
        </div>
        <Card title="Details">
          <DescriptionList
            items={[
              ["Type", humanize(data.rule_type)],
              ["Data source", humanize(data.detection_source)],
              ["Created", formatDateTime(data.created_at)],
              ["Updated", formatDateTime(data.updated_at)],
              [
                "Tags",
                data.tags.length ? (
                  <span className="flex flex-wrap gap-1">
                    {data.tags.map((tag) => (
                      <Badge key={tag}>{tag}</Badge>
                    ))}
                  </span>
                ) : null,
              ],
              ["Notes", data.notes],
            ]}
          />
        </Card>
      </div>
    </>
  )
}
