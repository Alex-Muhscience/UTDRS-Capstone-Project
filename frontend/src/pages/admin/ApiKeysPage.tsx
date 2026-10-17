import { Check, Copy, KeyRound, Plus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import type { ApiKey, ApiKeyWithSecret } from "@/api/client"
import { useApiKeys, useApiKeyScopes, useCreateApiKey, useRevokeApiKey } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { Table, Td, Th, Tr } from "@/components/ui/Table"
import { formatDateTime, formatRelative, humanize } from "@/lib/format"

const EXPIRY = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "", label: "Never" },
]

function keyState(key: ApiKey): { label: string; tone: "success" | "neutral" | "warning" } {
  if (key.revoked_at) return { label: "Revoked", tone: "neutral" }
  if (key.expires_at && new Date(key.expires_at) <= new Date()) return { label: "Expired", tone: "warning" }
  return { label: "Active", tone: "success" }
}

function NewKeyDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (result: ApiKeyWithSecret) => void }) {
  const scopes = useApiKeyScopes()
  const create = useCreateApiKey()
  const areas = [...new Set((scopes.data ?? []).map((scope) => scope.split(":")[0]))]

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="New API key"
      description="For a script, agent or integration. It can do what its scopes allow, never what only administrators can."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const chosen = data.getAll("scopes").map(String)
        if (chosen.length === 0) {
          toast.error("Choose at least one scope")
          return
        }
        const expiry = String(data.get("expires") ?? "")
        create.mutate(
          { name: String(data.get("name") ?? "").trim(), scopes: chosen, expires_in_days: expiry ? Number(expiry) : null },
          {
            onSuccess: (result) => {
              onClose()
              onCreated(result)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Create key
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" required>
          {(id) => <Input id={id} name="name" required maxLength={100} placeholder="firewall-forwarder" autoComplete="off" />}
        </Field>
        <Field label="Expires">{(id) => <Select id={id} name="expires" options={EXPIRY} defaultValue="90" />}</Field>
        <fieldset className="sm:col-span-2">
          <legend className="text-sm font-medium">Scopes</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {areas.map((area) => (
              <div key={area} className="flex items-center justify-between rounded-lg border border-border px-3 py-2 text-sm">
                <span>{humanize(area)}</span>
                <span className="flex gap-3">
                  {["read", "write"].map((access) => (
                    <label key={access} className="flex items-center gap-1.5 text-muted">
                      <input type="checkbox" name="scopes" value={`${area}:${access}`} className="size-4 accent-accent" />
                      {access}
                    </label>
                  ))}
                </span>
              </div>
            ))}
          </div>
        </fieldset>
      </div>
    </Dialog>
  )
}

function NewKeySecret({ result, onClose }: { result: ApiKeyWithSecret | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <Dialog
      open={result !== null}
      onClose={() => {
        setCopied(false)
        onClose()
      }}
      title="Your new API key"
      description="Copy it now and store it somewhere safe: it is shown only this once. Send it as Authorization: Bearer <key>."
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {result && (
        <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 p-3">
          <code className="flex-1 font-mono text-xs break-all" aria-label="API key">
            {result.key}
          </code>
          <Button
            size="sm"
            onClick={() => {
              void navigator.clipboard?.writeText(result.key)
              setCopied(true)
            }}
          >
            {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
      )}
    </Dialog>
  )
}

function RevokeDialog({ apiKey, onClose }: { apiKey: ApiKey | null; onClose: () => void }) {
  const revoke = useRevokeApiKey()
  return (
    <Dialog
      open={apiKey !== null}
      onClose={onClose}
      title={`Revoke ${apiKey?.name ?? "key"}?`}
      description="Anything using it stops working at once. This cannot be undone; create a new key to replace it."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="danger"
            loading={revoke.isPending}
            onClick={() =>
              apiKey &&
              revoke.mutate(apiKey.id, {
                onSuccess: () => {
                  toast.success(`Revoked ${apiKey.name}`)
                  onClose()
                },
                onError: (error) => toast.error(error.message),
              })
            }
          >
            Revoke key
          </Button>
        </>
      }
    >
      {apiKey && (
        <p className="text-sm text-muted">
          <code className="font-mono text-fg">utdrs_{apiKey.prefix}_…</code>, with {apiKey.scopes.join(", ")}.
        </p>
      )}
    </Dialog>
  )
}

export function ApiKeysPage() {
  const keys = useApiKeys()
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState<ApiKeyWithSecret | null>(null)
  const [revoking, setRevoking] = useState<ApiKey | null>(null)

  return (
    <>
      <PageHeader
        title="API keys"
        description="Credentials for scripts, agents and integrations, so they never need a person's password. Each key can use only the areas its scopes name."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="size-4" aria-hidden /> New key
          </Button>
        }
      />
      <Card bodyClassName="p-0">
        {keys.isPending ? (
          <SkeletonRows />
        ) : keys.isError ? (
          <ErrorState error={keys.error} onRetry={() => void keys.refetch()} />
        ) : keys.data.length === 0 ? (
          <EmptyState title="No API keys yet" action={<Button onClick={() => setCreating(true)}>Create a key</Button>}>
            Integrations that send events, or read alerts, each get their own key.
          </EmptyState>
        ) : (
          <Table label="API keys">
            <thead>
              <tr>
                <Th>Key</Th>
                <Th>Scopes</Th>
                <Th className="w-32">Last used</Th>
                <Th className="w-32">Expires</Th>
                <Th className="w-28">Status</Th>
                <Th className="w-28">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {keys.data.map((key) => {
                const state = keyState(key)
                return (
                  <Tr key={key.id}>
                    <Td className="max-w-0">
                      <span className="flex items-center gap-2 truncate font-medium">
                        <KeyRound className="size-3.5 shrink-0 text-subtle" aria-hidden /> {key.name}
                      </span>
                      <span className="block truncate text-xs text-subtle">
                        <code className="font-mono">utdrs_{key.prefix}_…</code> · by {String(key.created_by.name ?? "unknown")},{" "}
                        <span title={formatDateTime(key.created_at)}>{formatRelative(key.created_at)}</span>
                      </span>
                    </Td>
                    <Td>
                      <span className="flex flex-wrap gap-1">
                        {key.scopes.map((scope) => (
                          <Badge key={scope}>{scope}</Badge>
                        ))}
                      </span>
                    </Td>
                    <Td className="text-muted" title={formatDateTime(key.last_used_at)}>
                      {key.last_used_at ? formatRelative(key.last_used_at) : "Never"}
                    </Td>
                    <Td className="text-muted" title={formatDateTime(key.expires_at)}>
                      {key.expires_at ? formatRelative(key.expires_at) : "Never"}
                    </Td>
                    <Td>
                      <Badge tone={state.tone}>{state.label}</Badge>
                    </Td>
                    <Td className="text-right">
                      {state.label === "Active" && (
                        <Button size="sm" variant="danger" onClick={() => setRevoking(key)}>
                          Revoke
                        </Button>
                      )}
                    </Td>
                  </Tr>
                )
              })}
            </tbody>
          </Table>
        )}
      </Card>
      <NewKeyDialog open={creating} onClose={() => setCreating(false)} onCreated={setCreated} />
      <NewKeySecret result={created} onClose={() => setCreated(null)} />
      <RevokeDialog apiKey={revoking} onClose={() => setRevoking(null)} />
    </>
  )
}
