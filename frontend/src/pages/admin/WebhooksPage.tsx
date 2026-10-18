import { Check, Copy, Plus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import type { Webhook } from "@/api/client"
import {
  useCreateWebhook,
  useDeleteWebhook,
  useDeliveries,
  useRedeliver,
  useRotateWebhookSecret,
  useTestWebhook,
  useUpdateWebhook,
  useWebhookEvents,
  useWebhooks,
} from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import type { Tone } from "@/lib/tones"
import { formatDateTime, formatRelative } from "@/lib/format"

const DELIVERY_TONES: Record<string, Tone> = { queued: "neutral", sending: "accent", delivered: "success", failed: "danger" }

function SecretDialog({ secret, onClose }: { secret: string | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <Dialog
      open={secret !== null}
      onClose={onClose}
      title="Signing secret"
      description="Shown only this once. Your receiver checks each request's UTDRS-Signature header with it."
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className="space-y-3">
        <code className="block break-all rounded-lg bg-surface-2 p-3 font-mono text-sm">{secret}</code>
        <Button
          size="sm"
          onClick={() => {
            void navigator.clipboard?.writeText(secret ?? "")
            setCopied(true)
          }}
        >
          {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />} {copied ? "Copied" : "Copy"}
        </Button>
        <p className="text-xs text-muted">
          The header is <code>t=&lt;unix time&gt;,v1=&lt;HMAC-SHA256 of "&lt;t&gt;.&lt;body&gt;"&gt;</code>. Reject requests whose time is more than a few minutes old.
        </p>
      </div>
    </Dialog>
  )
}

function NewWebhookDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (secret: string) => void }) {
  const events = useWebhookEvents()
  const create = useCreateWebhook()
  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="New webhook"
      description="UTDRS sends each event you choose to this HTTPS address, signed, and retries for a day if it does not get through."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const chosen = data.getAll("events").map(String)
        if (!chosen.length) {
          toast.error("Choose at least one event")
          return
        }
        create.mutate(
          { name: String(data.get("name") ?? "").trim(), url: String(data.get("url") ?? "").trim(), events: chosen },
          {
            onSuccess: (webhook) => {
              onClose()
              onCreated(webhook.signing_secret)
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" required>
          {(id) => <Input id={id} name="name" required maxLength={100} placeholder="Ticketing system" />}
        </Field>
        <Field label="URL" required>
          {(id) => <Input id={id} name="url" type="url" required placeholder="https://hooks.example.com/utdrs" />}
        </Field>
        <fieldset className="sm:col-span-2">
          <legend className="text-sm font-medium">Events</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {(events.data ?? [])
              .filter((item) => item.name !== "ping")
              .map((item) => (
                <label key={item.name} className="flex items-start gap-2 rounded-lg border border-border px-3 py-2 text-sm">
                  <input type="checkbox" name="events" value={item.name} className="mt-0.5 size-4" />
                  <span>
                    <span className="block font-mono text-xs">{item.name}</span>
                    <span className="block text-xs text-muted">{item.description}</span>
                  </span>
                </label>
              ))}
          </div>
        </fieldset>
      </div>
    </Dialog>
  )
}

function Deliveries({ webhookId }: { webhookId: string }) {
  const deliveries = useDeliveries(webhookId)
  const redeliver = useRedeliver()
  if (deliveries.isPending) return <SkeletonRows rows={2} columns={3} />
  if (!deliveries.data?.length) return <p className="px-5 py-4 text-sm text-muted">Nothing sent yet. Use "Send a test" to try it.</p>
  return (
    <ul className="divide-y divide-border" aria-label="Deliveries">
      {deliveries.data.map((delivery) => (
        <li key={delivery.id} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-sm">
          <Badge tone={DELIVERY_TONES[delivery.status] ?? "neutral"}>
            {delivery.status === "queued" && delivery.attempts ? `Retrying (${delivery.attempts})` : delivery.status}
          </Badge>
          <span className="font-mono text-xs">{delivery.event}</span>
          <span className="min-w-0 flex-1 truncate text-xs text-muted" title={delivery.error ?? undefined}>
            {delivery.response_status ? `HTTP ${delivery.response_status}` : ""} {delivery.error ?? ""}
          </span>
          <span className="text-xs text-subtle" title={formatDateTime(delivery.created_at)}>
            {formatRelative(delivery.created_at)}
          </span>
          {(delivery.status === "failed" || delivery.status === "delivered") && (
            <Button size="sm" variant="ghost" disabled={redeliver.isPending} onClick={() => redeliver.mutate(delivery.id, { onError: (error) => toast.error(error.message) })}>
              Send again
            </Button>
          )}
        </li>
      ))}
    </ul>
  )
}

function WebhookCard({ webhook, onSecret }: { webhook: Webhook; onSecret: (secret: string) => void }) {
  const update = useUpdateWebhook()
  const test = useTestWebhook()
  const rotate = useRotateWebhookSecret()
  const remove = useDeleteWebhook()
  const [open, setOpen] = useState(false)
  return (
    <Card
      title={
        <span className="flex flex-wrap items-center gap-2">
          {webhook.name}
          {!webhook.enabled && <Badge>Off</Badge>}
          {webhook.last_status === "failing" && <Badge tone="danger">Failing</Badge>}
          {webhook.last_status === "ok" && <Badge tone="success">Delivering</Badge>}
        </span>
      }
      description={<span className="break-all font-mono">{webhook.url}</span>}
      bodyClassName="p-0"
    >
      <div className="space-y-3 px-5 py-4 text-sm">
        <p className="text-muted">
          {webhook.events.includes("*") ? "Every event" : webhook.events.join(", ")}
          {webhook.last_delivery_at ? ` · last sent ${formatRelative(webhook.last_delivery_at)}` : ""}
        </p>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={test.isPending} onClick={() => test.mutate(webhook.id, { onSuccess: () => { setOpen(true); toast.success("Test queued") }, onError: (error) => toast.error(error.message) })}>
            Send a test
          </Button>
          <Button size="sm" onClick={() => setOpen(!open)}>
            {open ? "Hide deliveries" : "Deliveries"}
          </Button>
          <Button size="sm" disabled={update.isPending} onClick={() => update.mutate({ webhookId: webhook.id, enabled: !webhook.enabled })}>
            {webhook.enabled ? "Turn off" : "Turn on"}
          </Button>
          <Button size="sm" disabled={rotate.isPending} onClick={() => rotate.mutate(webhook.id, { onSuccess: (result) => onSecret(result.signing_secret), onError: (error) => toast.error(error.message) })}>
            New secret
          </Button>
          <Button size="sm" variant="danger" disabled={remove.isPending} onClick={() => remove.mutate(webhook.id, { onSuccess: () => toast.success("Webhook deleted") })}>
            Delete
          </Button>
        </div>
      </div>
      {open && (
        <div className="border-t border-border">
          <Deliveries webhookId={webhook.id} />
        </div>
      )}
    </Card>
  )
}

export function WebhooksPage() {
  const webhooks = useWebhooks()
  const [creating, setCreating] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  return (
    <>
      <PageHeader
        title="Webhooks"
        description="Tell your other systems (ticketing, chat, your own automation) what happens in UTDRS, as it happens."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="size-4" aria-hidden /> New webhook
          </Button>
        }
      />
      {webhooks.isPending ? (
        <SkeletonRows rows={3} columns={2} />
      ) : webhooks.isError ? (
        <ErrorState error={webhooks.error} onRetry={() => void webhooks.refetch()} />
      ) : webhooks.data.length === 0 ? (
        <Card>
          <EmptyState title="No webhooks yet">Send new alerts, cases and response actions to another system.</EmptyState>
        </Card>
      ) : (
        <div className="space-y-4">
          {webhooks.data.map((webhook) => (
            <WebhookCard key={webhook.id} webhook={webhook} onSecret={setSecret} />
          ))}
        </div>
      )}
      <NewWebhookDialog open={creating} onClose={() => setCreating(false)} onCreated={setSecret} />
      <SecretDialog secret={secret} onClose={() => setSecret(null)} />
    </>
  )
}
