import { Search } from "lucide-react"
import { useEffect, useState } from "react"

import { cx } from "@/lib/cx"

import { controlClasses } from "./Field"

/** A search box that reports its value after typing pauses. */
export function SearchInput({
  value,
  onChange,
  placeholder,
  className,
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  className?: string
}) {
  const [draft, setDraft] = useState(value)
  const [prop, setProp] = useState(value)
  if (value !== prop) {
    // The URL changed elsewhere (back button, a link): follow it.
    setProp(value)
    setDraft(value)
  }

  useEffect(() => {
    if (draft.trim() === value) return
    const timer = window.setTimeout(() => onChange(draft.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [draft, value, onChange])

  return (
    <div className={cx("relative", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" aria-hidden />
      <input
        type="search"
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className={cx(controlClasses, "h-9 pl-9")}
      />
    </div>
  )
}
