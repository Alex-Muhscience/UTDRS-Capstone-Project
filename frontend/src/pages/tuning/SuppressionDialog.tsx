import { useState } from "react"
import { toast } from "sonner"

import type { SuppressionCreate, SuppressionSuggestion } from "@/api/client"
import { useCreateSuppression } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select } from "@/components/ui/Field"

const ENTITY_TYPES = ["user", "host", "asset", "ip", "sender", "file_hash", "message"] as const
const ENTITY_LABELS: Record<(typeof ENTITY_TYPES)[number], string> = {
  user: "A user",
  host: "A device, by name",
  asset: "A device, by asset id",
  ip: "An address",
  sender: "An email sender",
  file_hash: "A file, by hash",
  message: "An email, by message id",
}
const SEVERITIES = [
  { value: "low", label: "Low and below" },
  { value: "medium", label: "Medium and below" },
  { value: "high", label: "High and below (critical gets through)" },
  { value: "critical", label: "Everything, even critical" },
]
const EXPIRY = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "", label: "Never" },
]

/** Create a suppression: blank, or prefilled from an alert ("suppress alerts like this"). */
export function SuppressionDialog({ open, onClose, suggestion }: { open: boolean; onClose: () => void; suggestion?: SuppressionSuggestion | null }) {
  const isAdmin = useIsAdmin()
  const create = useCreateSuppression()
  const [entityType, setEntityType] = useState<string>(suggestion?.entity?.type ?? "")

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title={suggestion ? "Suppress alerts like this" : "New suppression"}
      description="Matching alerts are kept, marked suppressed, and reach nobody: no case, playbook or email. Everyone can see what is suppressed and why."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        const text = (name: string) => String(data.get(name) ?? "").trim()
        const entityValue = text("entity_value")
        const expiry = text("expires")
        const body: SuppressionCreate = {
          name: text("name"),
          reason: text("reason"),
          title_contains: text("title_contains") || null,
          detector: data.get("use_detector") ? suggestion?.detector || null : null,
          entity: entityType && entityValue ? { type: entityType as (typeof ENTITY_TYPES)[number], value: entityValue } : null,
          max_severity: text("max_severity") as SuppressionCreate["max_severity"],
          expires_in_days: expiry ? Number(expiry) : null,
        }
        create.mutate(body, {
          onSuccess: () => {
            toast.success("Suppression created")
            onClose()
          },
          onError: (error) => toast.error(error.message),
        })
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Suppress
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" required>
          {(id) => <Input id={id} name="name" required maxLength={100} defaultValue={suggestion?.name ?? ""} />}
        </Field>
        <Field label="Why" required>
          {(id) => <Input id={id} name="reason" required maxLength={500} placeholder="Our vulnerability scanner" />}
        </Field>
        {suggestion?.detector ? (
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input type="checkbox" name="use_detector" defaultChecked className="size-4" /> Only alerts from the same detector
          </label>
        ) : (
          <Field label="Title contains" className="sm:col-span-2">
            {(id) => <Input id={id} name="title_contains" maxLength={200} placeholder="Port scan" defaultValue={suggestion?.name ?? ""} />}
          </Field>
        )}
        <Field label="Involving">
          {(id) => (
            <Select
              id={id}
              value={entityType}
              placeholder="Anyone or anything"
              options={ENTITY_TYPES.map((type) => ({ value: type, label: ENTITY_LABELS[type] }))}
              onChange={(event) => setEntityType(event.target.value)}
            />
          )}
        </Field>
        <Field label="Which one">
          {(id) => <Input id={id} name="entity_value" disabled={!entityType} defaultValue={suggestion?.entity?.value ?? ""} placeholder="10.0.0.9" />}
        </Field>
        <Field label="Up to severity">
          {(id) => (
            <Select
              id={id}
              name="max_severity"
              defaultValue={suggestion?.max_severity ?? "high"}
              options={isAdmin ? SEVERITIES : SEVERITIES.filter((option) => option.value !== "critical")}
            />
          )}
        </Field>
        <Field label="For">
          {(id) => <Select id={id} name="expires" defaultValue="90" options={isAdmin ? EXPIRY : EXPIRY.filter((option) => option.value)} />}
        </Field>
      </div>
    </Dialog>
  )
}
