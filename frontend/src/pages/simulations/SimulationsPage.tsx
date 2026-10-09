import { Play, Plus, Square } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { useCreateSimulation, useRunSimulation, useSimulations } from "@/api/queries"
import { Badge, StatusBadge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select, Textarea } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { SIMULATION_INTENSITIES, SIMULATION_SCENARIOS, SIMULATION_SCOPES } from "@/lib/constants"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

const FILTERS = ["status"] as const

function NewSimulationDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateSimulation()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Plan a simulation"
      description="Record an attack-simulation exercise, then start and stop it as it runs."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const value = (name: string) => String(data.get(name) ?? "").trim()
        create.mutate(
          {
            name: value("name"),
            description: value("description"),
            scenario_type: value("scenario_type"),
            scope: value("scope"),
            intensity: value("intensity"),
            status: "idle",
            target_assets: [],
          },
          {
            onSuccess: (simulation) => {
              toast.success(`Planned ${simulation.name}`)
              onClose()
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Plan simulation
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Name" required className="sm:col-span-3">
          {(id) => <Input id={id} name="name" required placeholder="Quarterly ransomware drill" />}
        </Field>
        <Field label="Scenario" required>
          {(id) => <Select id={id} name="scenario_type" options={SIMULATION_SCENARIOS} defaultValue="ransomware" />}
        </Field>
        <Field label="Scope" required>
          {(id) => <Select id={id} name="scope" options={SIMULATION_SCOPES} defaultValue="endpoint" />}
        </Field>
        <Field label="Intensity">
          {(id) => <Select id={id} name="intensity" options={SIMULATION_INTENSITIES} defaultValue="low" />}
        </Field>
        <Field label="Description" required className="sm:col-span-3">
          {(id) => <Textarea id={id} name="description" required placeholder="What the exercise tests and who is involved." />}
        </Field>
      </div>
    </Dialog>
  )
}

export function SimulationsPage() {
  const [planning, setPlanning] = useState(false)
  const { filters, page, setFilter, setPage } = useUrlFilters(FILTERS)
  const simulations = useSimulations({ status: filters.status, page })
  const run = useRunSimulation()

  function control(simulationId: string, action: "start" | "stop", name: string) {
    run.mutate(
      { simulationId, action },
      {
        onSuccess: () => toast.success(`${action === "start" ? "Started" : "Stopped"} ${name}`),
        onError: (error) => toast.error(error.message),
      },
    )
  }

  return (
    <>
      <PageHeader
        title="Simulations"
        description="Attack-simulation exercises: plan them, record when they run, and review what they produced."
        actions={
          <Button variant="primary" onClick={() => setPlanning(true)}>
            <Plus className="size-4" aria-hidden /> Plan simulation
          </Button>
        }
      />
      <Card bodyClassName="p-0">
        <div className="flex border-b border-border p-4">
          <Select
            aria-label="Status"
            value={filters.status}
            onChange={(event) => setFilter("status", event.target.value)}
            options={["idle", "running", "completed", "failed"]}
            placeholder="Any status"
            className="w-44"
          />
        </div>
        {simulations.isPending ? (
          <SkeletonRows />
        ) : simulations.isError ? (
          <ErrorState error={simulations.error} onRetry={() => void simulations.refetch()} />
        ) : simulations.data.rows.length === 0 ? (
          <EmptyState title="No simulations" action={<Button onClick={() => setPlanning(true)}>Plan one</Button>}>
            Exercises such as a ransomware drill check that detection and response work before a real incident.
          </EmptyState>
        ) : (
          <Table label="Simulations">
            <thead>
              <tr>
                <Th>Simulation</Th>
                <Th className="w-40">Scenario</Th>
                <Th className="w-28">Intensity</Th>
                <Th className="w-28">Status</Th>
                <Th className="w-32">Created</Th>
                <Th className="w-28">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {simulations.data.rows.map((simulation) => (
                <Tr key={simulation.id}>
                  <Td className="max-w-0">
                    <span className="block truncate font-medium">{simulation.name}</span>
                    <span className="block truncate text-xs text-subtle">{simulation.description}</span>
                  </Td>
                  <Td className="text-muted">
                    {humanize(simulation.scenario_type)}
                    <span className="block text-xs text-subtle">{humanize(simulation.scope)} scope</span>
                  </Td>
                  <Td>
                    <Badge>{humanize(simulation.intensity)}</Badge>
                  </Td>
                  <Td>
                    <StatusBadge status={simulation.status} />
                  </Td>
                  <Td className="text-muted" title={formatDateTime(simulation.created_at)}>
                    {formatRelative(simulation.created_at)}
                  </Td>
                  <Td className="text-right">
                    {simulation.status === "running" ? (
                      <Button size="sm" onClick={() => control(simulation.id, "stop", simulation.name)} disabled={run.isPending}>
                        <Square className="size-3.5" aria-hidden /> Stop
                      </Button>
                    ) : (
                      <Button size="sm" onClick={() => control(simulation.id, "start", simulation.name)} disabled={run.isPending}>
                        <Play className="size-3.5" aria-hidden /> Start
                      </Button>
                    )}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {simulations.data && (
          <Pagination page={page} hasMore={simulations.data.hasMore} onPage={setPage} fetching={simulations.isFetching} />
        )}
      </Card>
      <NewSimulationDialog open={planning} onClose={() => setPlanning(false)} />
    </>
  )
}
