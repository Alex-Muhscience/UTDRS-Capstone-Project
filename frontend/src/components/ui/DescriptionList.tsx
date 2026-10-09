import type { ReactNode } from "react"

/** Label/value pairs; empty values show as a dash. */
export function DescriptionList({ items }: { items: Array<[label: string, value: ReactNode]> }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2">
      {items.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-xs font-medium text-subtle">{label}</dt>
          <dd className="mt-1 text-sm break-words">{value === null || value === undefined || value === "" ? "—" : value}</dd>
        </div>
      ))}
    </dl>
  )
}
