import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react"

import { cx } from "@/lib/cx"
import { humanize } from "@/lib/format"

export const controlClasses =
  "w-full rounded-lg border border-border bg-surface-2 px-3 text-sm text-fg placeholder:text-subtle transition-colors hover:border-border-strong focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25 disabled:opacity-60"

/** A labelled form control. The control receives the generated id through render props. */
export function Field({
  label,
  hint,
  error,
  required,
  children,
  className,
}: {
  label: ReactNode
  hint?: ReactNode
  error?: ReactNode
  required?: boolean
  children: (id: string, describedBy: string | undefined) => ReactNode
  className?: string
}) {
  const id = useId()
  const hintId = hint || error ? `${id}-hint` : undefined
  return (
    <div className={cx("space-y-1.5", className)}>
      <label htmlFor={id} className="block text-xs font-medium text-muted">
        {label}
        {required && <span className="text-danger"> *</span>}
      </label>
      {children(id, hintId)}
      {(hint || error) && (
        <p id={hintId} className={cx("text-xs", error ? "text-danger" : "text-subtle")}>
          {error || hint}
        </p>
      )}
    </div>
  )
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(controlClasses, "h-9", className)} {...props} />
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(controlClasses, "min-h-24 py-2", className)} {...props} />
}

export function Select({
  options,
  placeholder,
  className,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & {
  options: readonly string[] | ReadonlyArray<{ value: string; label: string }>
  placeholder?: string
}) {
  return (
    <select className={cx(controlClasses, "h-9 pr-8", className)} {...props}>
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((option) => {
        const { value, label } = typeof option === "string" ? { value: option, label: humanize(option) } : option
        return (
          <option key={value} value={value}>
            {label}
          </option>
        )
      })}
    </select>
  )
}
