import { Check, Copy, Plus } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import type { ChatChannel } from "@/api/client"
import {
  useChatChannels,
  useChatEvents,
  useChatMessages,
  useCreateChatChannel,
  useDeleteChatChannel,
  useTestChatChannel,
  useUpdateChatChannel,
  type NewChatChannel,
} from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime, formatRelative } from "@/lib/format"

const KINDS: Array<{ value: NewChatChannel["kind"]; label: string; help: string }> = [
  { value: "teams", label: "Microsoft Teams", help: "In the Teams channel: ⋯ > Workflows > \"Post to a channel when a webhook request is received\". Copy the URL it gives." },
  { value: "slack_webhook", label: "Slack (webhook)", help: "Messages only. In Slack: create an app, turn on Incoming Webhooks, add one for the channel, and copy its URL." },
  {
    value: "slack_app",
    label: "Slack (app, with approvals)",
    help: "Messages, and Approve and Reject buttons. Your Slack app needs the chat:write and users:read.email permissions, must be in the channel, and needs Interactivity turned on with the Request URL shown after you add it.",
  },
]
const KIND_LABELS: Record<string, string> = Object.fromEntries(KINDS.map((kind) => [kind.value, kind.label]))
const SEVERITIES = ["critical", "high", "medium", "low", "info"].map((value) => ({ value, label: value[0]!.toUpperCase() + value.slice(1) }))

function NewChannelDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const events = useChatEvents()
  const create = useCreateChatChannel()
  const [kind, setKind] = useState<NewChatChannel["kind"]>("teams")
  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Add a channel"
      description="Where UTDRS tells your team about what needs attention."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const value = (name: string) => String(data.get(name) ?? "").trim() || undefined
        const chosen = data.getAll("events").map(String)
        if (!chosen.length) {
          toast.error("Choose at least one event")
          return
        }
        create.mutate(
          {
            name: value("name") ?? KIND_LABELS[kind] ?? kind,
            kind,
            events: chosen,
            min_alert_severity: (value("min_alert_severity") ?? "high") as NewChatChannel["min_alert_severity"],
            webhook_url: value("webhook_url"),
            bot_token: value("bot_token"),
            signing_secret: value("signing_secret"),
            slack_channel: value("slack_channel"),
          },
          {
            onSuccess: (channel) => {
              toast.success(`${channel.name} added: send a test to check it`)
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
            Add
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <fieldset>
          <legend className="text-sm font-medium">Where</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-3">
            {KINDS.map((option) => (
              <label key={option.value} className="flex items-start gap-2 rounded-lg border border-border px-3 py-2 text-sm">
                <input type="radio" name="kind" value={option.value} checked={kind === option.value} onChange={() => setKind(option.value)} className="mt-0.5" />
                {option.label}
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted">{KINDS.find((option) => option.value === kind)?.help}</p>
        </fieldset>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" required>
            {(id) => <Input id={id} name="name" required maxLength={100} placeholder="Security team" />}
          </Field>
          <Field label="Alerts from">
            {(id) => <Select id={id} name="min_alert_severity" options={SEVERITIES} defaultValue="high" />}
          </Field>
          {kind === "slack_app" ? (
            <>
              <Field label="Bot token" required hint="xoxb-…">
                {(id) => <Input id={id} name="bot_token" required autoComplete="off" />}
              </Field>
              <Field label="Signing secret" required>
                {(id) => <Input id={id} name="signing_secret" type="password" required autoComplete="off" />}
              </Field>
              <Field label="Channel id" required hint="In Slack: the channel's details, at the bottom (C…)">
                {(id) => <Input id={id} name="slack_channel" required autoComplete="off" />}
              </Field>
            </>
          ) : (
            <Field label="Webhook URL" required className="sm:col-span-2" hint="Kept encrypted: it lets anyone post to the channel">
              {(id) => <Input id={id} name="webhook_url" type="url" required autoComplete="off" />}
            </Field>
          )}
        </div>
        <fieldset>
          <legend className="text-sm font-medium">Tell it about</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {(events.data ?? []).map((item) => (
              <label key={item.name} className="flex items-start gap-2 rounded-lg border border-border px-3 py-2 text-sm">
                <input
                  type="checkbox"
                  name="events"
                  value={item.name}
                  defaultChecked={["alert.created", "action.approval_requested", "action.failed"].includes(item.name)}
                  className="mt-0.5 size-4"
                />
                <span className="text-xs">{item.description}</span>
              </label>
            ))}
          </div>
        </fieldset>
      </div>
    </Dialog>
  )
}

function CopyField({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 truncate rounded bg-surface-2 px-2 py-1 font-mono text-xs" title={value}>
        {value}
      </code>
      <Button
        size="sm"
        variant="ghost"
        aria-label="Copy the Request URL"
        onClick={() => {
          void navigator.clipboard?.writeText(value)
          setCopied(true)
        }}
      >
        {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
      </Button>
    </div>
  )
}

function Messages({ channelId }: { channelId: string }) {
  const messages = useChatMessages(channelId)
  if (messages.isPending) return <SkeletonRows rows={2} columns={3} />
  if (!messages.data?.length) return <p className="px-5 py-3 text-sm text-muted">Nothing sent yet.</p>
  return (
    <ul className="divide-y divide-border" aria-label="Messages sent">
      {messages.data.map((message) => (
        <li key={message.id} className="flex flex-wrap items-center gap-3 px-5 py-2 text-sm">
          <Badge tone={message.status === "sent" ? "success" : message.status === "failed" ? "danger" : "neutral"}>
            {message.status === "queued" && message.attempts ? `Retrying (${message.attempts})` : message.status}
          </Badge>
          <span className="font-mono text-xs">{message.event}</span>
          <span className="min-w-0 flex-1 truncate text-xs text-muted" title={message.error ?? undefined}>
            {message.error ?? ""}
          </span>
          <span className="text-xs text-subtle" title={formatDateTime(message.created_at)}>
            {formatRelative(message.created_at)}
          </span>
        </li>
      ))}
    </ul>
  )
}

function ChannelCard({ channel }: { channel: ChatChannel }) {
  const update = useUpdateChatChannel()
  const test = useTestChatChannel()
  const remove = useDeleteChatChannel()
  const [open, setOpen] = useState(false)
  return (
    <Card
      title={
        <span className="flex flex-wrap items-center gap-2">
          {channel.name}
          <Badge>{KIND_LABELS[channel.kind] ?? channel.kind}</Badge>
          {!channel.enabled && <Badge>Off</Badge>}
          {channel.last_status === "failing" && <Badge tone="danger">Failing</Badge>}
          {channel.last_status === "ok" && <Badge tone="success">Delivering</Badge>}
        </span>
      }
      description={`${channel.events.join(", ")} · alerts from ${channel.min_alert_severity}${channel.last_sent_at ? ` · last sent ${formatRelative(channel.last_sent_at)}` : ""}`}
      bodyClassName="p-0"
    >
      <div className="space-y-3 px-5 py-4 text-sm">
        {channel.last_status === "failing" && channel.last_error && <p className="text-danger">{channel.last_error}</p>}
        {channel.interactions_url && (
          <div className="space-y-1">
            <p className="text-xs text-muted">Request URL for your Slack app (Interactivity & Shortcuts), so Approve and Reject work:</p>
            <CopyField value={channel.interactions_url} />
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            disabled={test.isPending}
            onClick={() => test.mutate(channel.id, { onSuccess: () => toast.success("Test sent: check the channel"), onError: (error) => toast.error(error.message) })}
          >
            Send a test
          </Button>
          <Button size="sm" onClick={() => setOpen(!open)}>
            {open ? "Hide messages" : "Messages"}
          </Button>
          <Button size="sm" disabled={update.isPending} onClick={() => update.mutate({ id: channel.id, enabled: !channel.enabled })}>
            {channel.enabled ? "Turn off" : "Turn on"}
          </Button>
          <Button size="sm" variant="danger" disabled={remove.isPending} onClick={() => remove.mutate(channel.id, { onSuccess: () => toast.success(`${channel.name} removed`) })}>
            Remove
          </Button>
        </div>
      </div>
      {open && (
        <div className="border-t border-border">
          <Messages channelId={channel.id} />
        </div>
      )}
    </Card>
  )
}

export function ChatPage() {
  const channels = useChatChannels()
  const [adding, setAdding] = useState(false)
  return (
    <div className="space-y-6">
      <PageHeader
        title="Slack and Teams"
        description="Serious alerts, decisions waiting and failures, where your team already talks. With a Slack app, response actions can be approved from Slack by people whose role allows it."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <Plus className="size-4" aria-hidden /> Add a channel
          </Button>
        }
      />
      {channels.isPending ? (
        <SkeletonRows rows={3} columns={3} />
      ) : channels.isError ? (
        <ErrorState error={channels.error} onRetry={() => void channels.refetch()} />
      ) : !channels.data.length ? (
        <Card>
          <EmptyState title="No channels yet">Add a Teams or Slack channel, then send a test.</EmptyState>
        </Card>
      ) : (
        <div className="space-y-4">
          {channels.data.map((channel) => (
            <ChannelCard key={channel.id} channel={channel} />
          ))}
        </div>
      )}
      <NewChannelDialog open={adding} onClose={() => setAdding(false)} />
    </div>
  )
}
