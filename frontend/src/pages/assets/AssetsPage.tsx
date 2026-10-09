import { Plus } from "lucide-react"
import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { toast } from "sonner"

import { useAssets, useCreateAsset } from "@/api/queries"
import { Badge, StatusBadge } from "@/components/ui/Badge"
import { toneForSeverity } from "@/lib/tones"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { SearchInput } from "@/components/ui/SearchInput"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { ASSET_STATUSES, ASSET_TYPES, CRITICALITIES } from "@/lib/constants"
import { formatRelative, humanize } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

const FILTERS = ["type", "criticality", "q"] as const

function NewAssetDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const create = useCreateAsset()

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add an asset"
      description="A device or service to track. Events and alerts can reference it by id."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const value = (name: string) => String(data.get(name) ?? "").trim() || null
        create.mutate(
          {
            name: value("name") ?? "",
            asset_type: value("asset_type") ?? "server",
            ip_address: value("ip_address"),
            mac_address: value("mac_address"),
            os: value("os"),
            owner: value("owner"),
            department: value("department"),
            location: value("location"),
            criticality: value("criticality") ?? "medium",
            status: value("status") ?? "active",
          },
          {
            onSuccess: (asset) => {
              toast.success(`Added ${asset.name}`)
              onClose()
              navigate(`/assets/${asset.id}`)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Add asset
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" required className="sm:col-span-2">
          {(id) => <Input id={id} name="name" required placeholder="web-01" />}
        </Field>
        <Field label="Type" required>
          {(id) => <Select id={id} name="asset_type" options={ASSET_TYPES} defaultValue="server" required />}
        </Field>
        <Field label="Criticality">
          {(id) => <Select id={id} name="criticality" options={CRITICALITIES} defaultValue="medium" />}
        </Field>
        <Field label="IP address">{(id) => <Input id={id} name="ip_address" className="font-mono" placeholder="10.0.0.5" />}</Field>
        <Field label="MAC address">{(id) => <Input id={id} name="mac_address" className="font-mono" />}</Field>
        <Field label="Operating system">{(id) => <Input id={id} name="os" placeholder="Ubuntu 24.04" />}</Field>
        <Field label="Status">{(id) => <Select id={id} name="status" options={ASSET_STATUSES} defaultValue="active" />}</Field>
        <Field label="Owner">{(id) => <Input id={id} name="owner" />}</Field>
        <Field label="Department">{(id) => <Input id={id} name="department" />}</Field>
        <Field label="Location" className="sm:col-span-2">{(id) => <Input id={id} name="location" />}</Field>
      </div>
    </Dialog>
  )
}

export function AssetsPage() {
  const navigate = useNavigate()
  const [adding, setAdding] = useState(false)
  const { filters, page, setFilter, setPage } = useUrlFilters(FILTERS)
  const assets = useAssets({ assetType: filters.type, criticality: filters.criticality, search: filters.q, page })
  const filtered = Boolean(filters.type || filters.criticality || filters.q)

  return (
    <>
      <PageHeader
        title="Assets"
        description="The devices and services being protected, with their known vulnerabilities."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <Plus className="size-4" aria-hidden /> Add asset
          </Button>
        }
      />
      <Card bodyClassName="p-0">
        <div className="flex flex-col gap-2 border-b border-border p-4 sm:flex-row">
          <Select
            aria-label="Asset type"
            value={filters.type}
            onChange={(event) => setFilter("type", event.target.value)}
            options={ASSET_TYPES}
            placeholder="Any type"
            className="sm:w-44"
          />
          <Select
            aria-label="Criticality"
            value={filters.criticality}
            onChange={(event) => setFilter("criticality", event.target.value)}
            options={CRITICALITIES}
            placeholder="Any criticality"
            className="sm:w-44"
          />
          <SearchInput value={filters.q} onChange={(value) => setFilter("q", value)} placeholder="Search assets" className="sm:ml-auto sm:w-72" />
        </div>
        {assets.isPending ? (
          <SkeletonRows />
        ) : assets.isError ? (
          <ErrorState error={assets.error} onRetry={() => void assets.refetch()} />
        ) : assets.data.rows.length === 0 ? (
          <EmptyState
            title={filtered ? "No matching assets" : "No assets yet"}
            action={!filtered && <Button onClick={() => setAdding(true)}>Add an asset</Button>}
          >
            {filtered ? "Try a different filter or search." : "Add the servers, workstations and devices you want to protect."}
          </EmptyState>
        ) : (
          <Table label="Assets">
            <thead>
              <tr>
                <Th>Asset</Th>
                <Th className="w-36">IP address</Th>
                <Th className="w-28">Criticality</Th>
                <Th className="w-28">Status</Th>
                <Th className="w-32">Vulnerabilities</Th>
                <Th className="w-32">Last seen</Th>
              </tr>
            </thead>
            <tbody>
              {assets.data.rows.map((asset) => (
                <Tr key={asset.id} onClick={() => navigate(`/assets/${asset.id}`)}>
                  <Td className="max-w-0">
                    <Link
                      to={`/assets/${asset.id}`}
                      className="block truncate font-medium hover:text-accent"
                      onClick={(event) => event.stopPropagation()}
                    >
                      {asset.name}
                    </Link>
                    <span className="block truncate text-xs text-subtle">
                      {humanize(asset.asset_type)}
                      {asset.os && ` · ${asset.os}`}
                    </span>
                  </Td>
                  <Td className="font-mono text-xs text-muted">{asset.ip_address ?? "—"}</Td>
                  <Td>
                    <Badge tone={toneForSeverity(asset.criticality)} dot>
                      {humanize(asset.criticality)}
                    </Badge>
                  </Td>
                  <Td>
                    <StatusBadge status={asset.status} />
                  </Td>
                  <Td className="tabular-nums">
                    {asset.vulnerabilities.length ? (
                      <Badge tone="danger">{asset.vulnerabilities.length} known</Badge>
                    ) : (
                      <span className="text-subtle">None</span>
                    )}
                  </Td>
                  <Td className="text-muted">{formatRelative(asset.last_seen)}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {assets.data && <Pagination page={page} hasMore={assets.data.hasMore} onPage={setPage} fetching={assets.isFetching} />}
      </Card>
      <NewAssetDialog open={adding} onClose={() => setAdding(false)} />
    </>
  )
}
