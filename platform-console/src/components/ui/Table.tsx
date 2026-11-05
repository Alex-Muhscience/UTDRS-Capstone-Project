import type { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react"

import { cx } from "@/lib/cx"

export function Table({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-sm" aria-label={label}>
        {children}
      </table>
    </div>
  )
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={cx(
        "border-b border-border px-4 py-2.5 text-left text-xs font-medium tracking-wide text-subtle uppercase first:pl-5 last:pr-5",
        className,
      )}
      {...props}
    />
  )
}

export function Tr({ className, onClick, ...props }: HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cx(
        "border-b border-border last:border-0",
        onClick && "cursor-pointer transition-colors hover:bg-surface-2",
        className,
      )}
      onClick={onClick}
      {...props}
    />
  )
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cx("px-4 py-3 align-middle first:pl-5 last:pr-5", className)} {...props} />
}
