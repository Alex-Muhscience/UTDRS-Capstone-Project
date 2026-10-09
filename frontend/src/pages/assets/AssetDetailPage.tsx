import { useParams } from "react-router"
import { toast } from "sonner"

import { useAsset, useAssetVulnerability } from "@/api/queries"
import { Badge, StatusBadge } from "@/components/ui/Badge"
import { toneForSeverity } from "@/lib/tones"
import { BackLink } from "@/components/ui/BackLink"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { TagEditor } from "@/components/ui/TagEditor"
import { formatDateTime, humanize } from "@/lib/format"

export function AssetDetailPage() {
  const { assetId = "" } = useParams()
  const asset = useAsset(assetId)
  const vulnerability = useAssetVulnerability(assetId)

  if (asset.isPending) return <SkeletonRows rows={6} columns={2} />
  if (asset.isError) {
    return (
      <>
        <BackLink to="/assets">All assets</BackLink>
        <ErrorState error={asset.error} onRetry={() => void asset.refetch()} />
      </>
    )
  }

  const data = asset.data
  return (
    <>
      <PageHeader
        eyebrow={<BackLink to="/assets">All assets</BackLink>}
        title={data.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone={toneForSeverity(data.criticality)} dot>
              {humanize(data.criticality)} criticality
            </Badge>
            <StatusBadge status={data.status} />
            <span className="text-subtle">{humanize(data.asset_type)}</span>
          </span>
        }
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Details" className="xl:col-span-2">
          <DescriptionList
            items={[
              ["IP address", data.ip_address && <code className="font-mono text-xs">{data.ip_address}</code>],
              ["MAC address", data.mac_address && <code className="font-mono text-xs">{data.mac_address}</code>],
              ["Operating system", data.os],
              ["Owner", data.owner],
              ["Department", data.department],
              ["Location", data.location],
              ["Last seen", formatDateTime(data.last_seen)],
              ["Added", formatDateTime(data.created_at)],
              ["Asset id", <code key="id" className="font-mono text-xs">{data.id}</code>],
              ["Tags", data.tags.length ? data.tags.join(", ") : null],
            ]}
          />
        </Card>
        <Card title="Known vulnerabilities" description="CVE identifiers or advisory references">
          <TagEditor
            label="Vulnerabilities"
            mono
            values={data.vulnerabilities}
            placeholder="CVE-2024-3094"
            busy={vulnerability.isPending}
            onAdd={(value) => vulnerability.mutate({ vulnerability: value }, { onError: (error) => toast.error(error.message) })}
            onRemove={(value) =>
              vulnerability.mutate({ vulnerability: value, remove: true }, { onError: (error) => toast.error(error.message) })
            }
          />
        </Card>
      </div>
    </>
  )
}
