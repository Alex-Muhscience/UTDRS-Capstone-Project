import type { ReactNode } from "react"

import { cx } from "@/lib/cx"

export function Card({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={cx("min-w-0 rounded-xl border border-border bg-surface shadow-card", className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      {/* bodyClassName replaces the default padding rather than competing with it. */}
      <div className={bodyClassName ?? "p-5"}>{children}</div>
    </section>
  )
}
