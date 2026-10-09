import { useState } from "react"
import { useNavigate } from "react-router"
import { toast } from "sonner"

import type { EventCreate } from "@/api/client"
import { useCreateEvent } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input, Select, Textarea } from "@/components/ui/Field"
import { EVENT_TYPES } from "@/lib/constants"
import { cx } from "@/lib/cx"

type Preset = {
  id: string
  label: string
  summary: string
  event: Omit<EventCreate, "timestamp">
}

const PRESETS: Preset[] = [
  {
    id: "ransomware",
    label: "Shadow copies deleted",
    summary: "A ransomware preparation step (MITRE T1490). The engine raises a critical alert.",
    event: {
      event_type: "process",
      source: "endpoint_agent",
      user_id: "jsmith",
      description: "Shadow copies deleted",
      raw_data: { process_name: "vssadmin.exe", command_line: "vssadmin delete shadows /all /quiet" },
    },
  },
  {
    id: "benign",
    label: "Editor opened",
    summary: "Routine activity. The engine finds nothing and marks the event clean.",
    event: {
      event_type: "process",
      source: "endpoint_agent",
      user_id: "jsmith",
      description: "Editor opened",
      raw_data: { process_name: "notepad.exe", command_line: "notepad.exe notes.txt" },
    },
  },
  {
    id: "custom",
    label: "Custom",
    summary: "Write your own event.",
    event: { event_type: "network", source: "firewall", description: "", raw_data: {} },
  },
]

/** Send an event to the gateway and follow it through the core engine's analysis. */
export function TestEventDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const create = useCreateEvent()
  const [presetId, setPresetId] = useState("ransomware")
  const preset = PRESETS.find((candidate) => candidate.id === presetId) ?? PRESETS[0]!
  const [rawError, setRawError] = useState<string | null>(null)

  function submit(form: HTMLFormElement) {
    const data = new FormData(form)
    const value = (name: string) => String(data.get(name) ?? "").trim()
    let raw: Record<string, unknown>
    try {
      raw = JSON.parse(value("raw_data") || "{}") as Record<string, unknown>
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error()
    } catch {
      setRawError("Raw data must be a JSON object.")
      return
    }
    setRawError(null)
    create.mutate(
      {
        timestamp: new Date().toISOString(),
        event_type: value("event_type"),
        source: value("source"),
        description: value("description"),
        user_id: value("user_id") || null,
        source_ip: value("source_ip") || null,
        destination_ip: value("destination_ip") || null,
        raw_data: raw,
      },
      {
        onSuccess: (event) => {
          onClose()
          navigate(`/events/${event.id}`)
        },
        onError: (error) => toast.error(error.message),
      },
    )
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Send a test event"
      description="The gateway stores the event and passes it to the core engine; its verdict appears on the event."
      onSubmit={(event) => submit(event.currentTarget)}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Send event
          </Button>
        </>
      }
    >
      <fieldset>
        <legend className="mb-2 text-xs font-medium text-muted">Start from</legend>
        <div className="grid gap-2 sm:grid-cols-3">
          {PRESETS.map((candidate) => (
            <label
              key={candidate.id}
              className={cx(
                "cursor-pointer rounded-lg border p-3 text-sm transition-colors",
                candidate.id === presetId ? "border-accent bg-accent/8" : "border-border hover:border-border-strong",
              )}
            >
              <input
                type="radio"
                name="preset"
                value={candidate.id}
                checked={candidate.id === presetId}
                onChange={() => setPresetId(candidate.id)}
                className="sr-only"
              />
              <span className="block font-medium">{candidate.label}</span>
              <span className="mt-1 block text-xs text-muted">{candidate.summary}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {/* Keyed by preset so choosing one resets the fields to its values. */}
      <div key={preset.id} className="grid gap-4 sm:grid-cols-2">
        <Field label="Event type" required>
          {(id) => (
            <Select id={id} name="event_type" defaultValue={preset.event.event_type} options={EVENT_TYPES} required />
          )}
        </Field>
        <Field label="Source" required>
          {(id) => <Input id={id} name="source" defaultValue={preset.event.source} required />}
        </Field>
        <Field label="Description" required className="sm:col-span-2">
          {(id) => <Input id={id} name="description" defaultValue={preset.event.description} required />}
        </Field>
        <Field label="User">
          {(id) => <Input id={id} name="user_id" defaultValue={preset.event.user_id ?? ""} />}
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Source IP">{(id) => <Input id={id} name="source_ip" className="font-mono" />}</Field>
          <Field label="Destination IP">{(id) => <Input id={id} name="destination_ip" className="font-mono" />}</Field>
        </div>
        <Field
          label="Raw data (JSON)"
          className="sm:col-span-2"
          error={rawError}
          hint="Fields the detectors read, such as process_name and command_line."
        >
          {(id, describedBy) => (
            <Textarea
              id={id}
              name="raw_data"
              defaultValue={JSON.stringify(preset.event.raw_data, null, 2)}
              className="font-mono text-xs"
              aria-describedby={describedBy}
              spellCheck={false}
            />
          )}
        </Field>
      </div>
    </Dialog>
  )
}
