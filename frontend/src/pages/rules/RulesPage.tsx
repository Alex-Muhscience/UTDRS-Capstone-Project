import { Plus } from "lucide-react"
import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { toast } from "sonner"

import { useCreateRule, useRules } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { SeverityBadge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select, Textarea } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { SearchInput } from "@/components/ui/SearchInput"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { DETECTION_SOURCES, RULE_STATUSES, RULE_TYPES, SEVERITIES } from "@/lib/constants"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"
import { useUrlFilters } from "@/lib/useUrlFilters"

import { EngineBadge } from "./EngineBadge"
import { RuleStatusSelect } from "./RuleStatusSelect"
import { RuleSyncNotice } from "./RuleSyncNotice"

const FILTERS = ["status", "severity", "q"] as const

function NewRuleDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const create = useCreateRule()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="New detection rule"
      description="New rules start in testing, so they can be checked before they raise alerts."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const value = (name: string) => String(data.get(name) ?? "").trim()
        create.mutate(
          {
            name: value("name"),
            description: value("description"),
            rule_type: value("rule_type"),
            detection_source: value("detection_source"),
            severity: value("severity"),
            status: value("status"),
            logic: value("logic"),
            tags: value("tags")
              .split(",")
              .map((tag) => tag.trim())
              .filter(Boolean),
          },
          {
            onSuccess: (rule) => {
              toast.success(`Created ${rule.name}`)
              onClose()
              navigate(`/rules/${rule.id}`)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Create rule
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" required className="sm:col-span-2">
          {(id) => <Input id={id} name="name" required placeholder="vpn-brute-force" />}
        </Field>
        <Field label="Description" required className="sm:col-span-2">
          {(id) => <Input id={id} name="description" required placeholder="Many failed VPN logins from one address" />}
        </Field>
        <Field label="Type" required>
          {(id) => <Select id={id} name="rule_type" options={RULE_TYPES} defaultValue="signature" />}
        </Field>
        <Field label="Data source" required>
          {(id) => <Select id={id} name="detection_source" options={DETECTION_SOURCES} defaultValue="network" />}
        </Field>
        <Field label="Severity" required>
          {(id) => <Select id={id} name="severity" options={SEVERITIES} defaultValue="medium" />}
        </Field>
        <Field label="Status">{(id) => <Select id={id} name="status" options={RULE_STATUSES} defaultValue="testing" />}</Field>
        <Field
          label="Logic"
          required
          className="sm:col-span-2"
          hint="Comparisons joined by 'and' (or by 'or'): ==, !=, >, >=, <, <=, in [...], not in [...], matches '<regex>', contains, startswith, endswith, exists. Fields are event_type, source, or anything in the event's data."
        >
          {(id, describedBy) => (
            <Textarea
              id={id}
              name="logic"
              required
              spellCheck={false}
              className="font-mono text-xs"
              aria-describedby={describedBy}
              placeholder="process_name == 'powershell.exe' and command_line matches '(?i)-enc'"
            />
          )}
        </Field>
        <Field label="Tags" className="sm:col-span-2" hint="Comma separated, e.g. T1110, brute-force">
          {(id, describedBy) => <Input id={id} name="tags" aria-describedby={describedBy} />}
        </Field>
      </div>
    </Dialog>
  )
}

export function RulesPage() {
  const navigate = useNavigate()
  const isAdmin = useIsAdmin()
  const [creating, setCreating] = useState(false)
  const { filters, page, setFilter, setPage } = useUrlFilters(FILTERS)
  const rules = useRules({ status: filters.status, severity: filters.severity, search: filters.q, page })
  const filtered = Boolean(filters.status || filters.severity || filters.q)

  return (
    <>
      <PageHeader
        title="Detection rules"
        description="The rule catalogue: what each detection looks for, its severity and whether it is live."
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden /> New rule
            </Button>
          )
        }
      />
      <RuleSyncNotice />
      <Card bodyClassName="p-0">
        <div className="flex flex-col gap-2 border-b border-border p-4 sm:flex-row">
          <Select
            aria-label="Status"
            value={filters.status}
            onChange={(event) => setFilter("status", event.target.value)}
            options={RULE_STATUSES}
            placeholder="Any status"
            className="sm:w-40"
          />
          <Select
            aria-label="Severity"
            value={filters.severity}
            onChange={(event) => setFilter("severity", event.target.value)}
            options={SEVERITIES}
            placeholder="Any severity"
            className="sm:w-40"
          />
          <SearchInput value={filters.q} onChange={(value) => setFilter("q", value)} placeholder="Search rules" className="sm:ml-auto sm:w-72" />
        </div>
        {rules.isPending ? (
          <SkeletonRows />
        ) : rules.isError ? (
          <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />
        ) : rules.data.rows.length === 0 ? (
          <EmptyState
            title={filtered ? "No matching rules" : "No rules yet"}
            action={!filtered && isAdmin && <Button onClick={() => setCreating(true)}>Create a rule</Button>}
          >
            {filtered ? "Try a different filter or search." : "Rules describe what the detectors should look for."}
          </EmptyState>
        ) : (
          <Table label="Detection rules">
            <thead>
              <tr>
                <Th>Rule</Th>
                <Th className="w-32">Type</Th>
                <Th className="w-28">Severity</Th>
                <Th className="w-40">Status</Th>
                <Th className="w-24">Engine</Th>
                <Th className="w-32">Updated</Th>
              </tr>
            </thead>
            <tbody>
              {rules.data.rows.map((rule) => (
                <Tr key={rule.id} onClick={() => navigate(`/rules/${rule.id}`)}>
                  <Td className="max-w-0">
                    <Link
                      to={`/rules/${rule.id}`}
                      className="block truncate font-medium hover:text-accent"
                      onClick={(event) => event.stopPropagation()}
                    >
                      {rule.name}
                    </Link>
                    <span className="block truncate text-xs text-subtle">{rule.description}</span>
                  </Td>
                  <Td className="text-muted">
                    {humanize(rule.rule_type)}
                    <span className="block text-xs text-subtle">{humanize(rule.detection_source)}</span>
                  </Td>
                  <Td>
                    <SeverityBadge severity={rule.severity} />
                  </Td>
                  <Td>
                    <RuleStatusSelect ruleId={rule.id} status={rule.status} name={rule.name} />
                  </Td>
                  <Td>
                    <EngineBadge engine={rule.engine} />
                  </Td>
                  <Td className="text-muted" title={formatDateTime(rule.updated_at)}>
                    {formatRelative(rule.updated_at)}
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
        {rules.data && <Pagination page={page} hasMore={rules.data.hasMore} onPage={setPage} fetching={rules.isFetching} />}
      </Card>
      <NewRuleDialog open={creating} onClose={() => setCreating(false)} />
    </>
  )
}
