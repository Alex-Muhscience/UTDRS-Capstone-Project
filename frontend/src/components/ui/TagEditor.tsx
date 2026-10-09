import { Plus, X } from "lucide-react"
import { useState, type FormEvent } from "react"

import { Button } from "./Button"
import { Input } from "./Field"

/** A list of values with remove buttons and an input to add one. */
export function TagEditor({
  values,
  onAdd,
  onRemove,
  placeholder,
  label,
  busy,
  mono,
}: {
  values: string[]
  onAdd: (value: string) => void
  onRemove: (value: string) => void
  placeholder: string
  label: string
  busy?: boolean
  mono?: boolean
}) {
  const [draft, setDraft] = useState("")

  function submit(event: FormEvent) {
    event.preventDefault()
    const value = draft.trim()
    if (!value || values.includes(value)) return
    onAdd(value)
    setDraft("")
  }

  return (
    <div className="space-y-3">
      {values.length > 0 ? (
        <ul className="flex flex-wrap gap-1.5" aria-label={label}>
          {values.map((value) => (
            <li
              key={value}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 py-0.5 pr-1 pl-2 text-xs"
            >
              <span className={mono ? "font-mono" : undefined}>{value}</span>
              <button
                type="button"
                onClick={() => onRemove(value)}
                disabled={busy}
                className="rounded p-0.5 text-subtle hover:bg-surface-3 hover:text-fg"
                aria-label={`Remove ${value}`}
              >
                <X className="size-3" />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-subtle">None yet.</p>
      )}
      <form onSubmit={submit} className="flex gap-2">
        <Input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder={placeholder}
          aria-label={placeholder}
          className="h-8"
        />
        <Button type="submit" size="sm" disabled={!draft.trim() || busy}>
          <Plus className="size-3.5" aria-hidden /> Add
        </Button>
      </form>
    </div>
  )
}
