import { useState } from "react"
import { toast } from "sonner"

import type { ResponseSettings } from "@/api/client"
import { useActions, useResponseSettings, useUpdateResponseSettings } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input, Select, Textarea } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { Pagination } from "@/components/ui/Pagination"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"

import { ActionList } from "./ActionList"

const MODES = [
  { value: "approval", label: "Ask before acting (recommended)" },
  { value: "automatic", label: "Act on its own" },
  { value: "notify", label: "Only suggest" },
]

function SettingsForm({ settings }: { settings: ResponseSettings }) {
  const update = useUpdateResponseSettings()
  const [mode, setMode] = useState(settings.mode)
  const [limit, setLimit] = useState(String(settings.max_actions_per_hour))
  const [protectedAccounts, setProtectedAccounts] = useState(settings.protected_accounts.join("\n"))

  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault()
        update.mutate(
          { mode, max_actions_per_hour: Number(limit), protected_accounts: protectedAccounts.split(/[\n,]/).map((a) => a.trim()).filter(Boolean) },
          { onSuccess: () => toast.success("Response settings saved"), onError: (error) => toast.error(error.message) },
        )
      }}
    >
      <Field label="Playbooks may" hint="A playbook can be more cautious than this, never less.">
        {(id, describedBy) => (
          <Select id={id} aria-describedby={describedBy} value={mode} options={MODES} onChange={(event) => setMode(event.target.value as ResponseSettings["mode"])} />
        )}
      </Field>
      <Field label="Most actions on their own in an hour" hint="Beyond this, actions wait for a person.">
        {(id, describedBy) => (
          <Input id={id} aria-describedby={describedBy} type="number" min={0} max={1000} value={limit} onChange={(event) => setLimit(event.target.value)} />
        )}
      </Field>
      <Field label="Protected accounts" hint="One per line. Never disrupted automatically; only an administrator can approve it. Your UTDRS administrators are always protected.">
        {(id, describedBy) => (
          <Textarea id={id} aria-describedby={describedBy} value={protectedAccounts} onChange={(event) => setProtectedAccounts(event.target.value)} placeholder="ceo@example.com" />
        )}
      </Field>
      <Button type="submit" variant="primary" size="sm" loading={update.isPending}>
        Save
      </Button>
    </form>
  )
}

export function ResponsePage() {
  const isAdmin = useIsAdmin()
  const [page, setPage] = useState(0)
  const pending = useActions({ status: ["pending"] })
  const history = useActions({ page })
  const settings = useResponseSettings()

  return (
    <>
      <PageHeader title="Response" description="What UTDRS has done about threats, and what is waiting for your decision." />
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="Waiting for a decision" bodyClassName="p-0">
            {pending.isPending ? (
              <SkeletonRows rows={2} />
            ) : pending.isError ? (
              <ErrorState error={pending.error} onRetry={() => void pending.refetch()} />
            ) : pending.data.rows.length ? (
              <ActionList actions={pending.data.rows} showCase />
            ) : (
              <EmptyState title="Nothing is waiting for you">Actions playbooks suggest appear here for approval.</EmptyState>
            )}
          </Card>
          <Card title="All actions" bodyClassName="p-0">
            {history.isPending ? (
              <SkeletonRows rows={4} />
            ) : history.isError ? (
              <ErrorState error={history.error} onRetry={() => void history.refetch()} />
            ) : history.data.rows.length ? (
              <ActionList actions={history.data.rows} showCase />
            ) : (
              <EmptyState title="No actions yet" />
            )}
            {history.data && <Pagination page={page} hasMore={history.data.hasMore} onPage={setPage} fetching={history.isFetching} />}
          </Card>
        </div>
        <Card title="Safety limits" description={isAdmin ? undefined : "Set by your administrators."}>
          {settings.data ? (
            isAdmin ? (
              <SettingsForm settings={settings.data} />
            ) : (
              <dl className="space-y-2 text-sm">
                <div>
                  <dt className="text-xs text-subtle">Playbooks may</dt>
                  <dd>{MODES.find((m) => m.value === settings.data.mode)?.label}</dd>
                </div>
                <div>
                  <dt className="text-xs text-subtle">Most actions on their own in an hour</dt>
                  <dd>{settings.data.max_actions_per_hour}</dd>
                </div>
              </dl>
            )
          ) : (
            <SkeletonRows rows={3} columns={1} />
          )}
        </Card>
      </div>
    </>
  )
}
