import { Bell } from "lucide-react"
import { useEffect, useId, useRef, useState } from "react"
import { Link } from "react-router"

import { useInbox, useMarkRead, useUnreadCount } from "@/api/queries"
import { InboxItemRow } from "@/pages/inbox/InboxItemRow"

/** The notifications centre's bell: how many are unread, and the latest at a click. */
export function InboxBell() {
  const unread = useUnreadCount()
  const [open, setOpen] = useState(false)
  const panel = useId()
  const ref = useRef<HTMLDivElement>(null)
  const count = unread.data?.unread ?? 0

  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !ref.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", close)
    document.addEventListener("keydown", close)
    return () => {
      document.removeEventListener("mousedown", close)
      document.removeEventListener("keydown", close)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panel}
        aria-label={count ? `Notifications, ${count} unread` : "Notifications"}
        onClick={() => setOpen(!open)}
        className="relative grid size-9 place-items-center rounded-lg text-muted hover:bg-surface-2 hover:text-fg"
      >
        <Bell className="size-5" aria-hidden />
        {count > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-4 rounded-full bg-danger px-1 text-center text-[10px] leading-4 font-semibold text-white tabular-nums">
            {count > 99 ? "99+" : count}
          </span>
        )}
      </button>
      {open && <Panel id={panel} onClose={() => setOpen(false)} unread={count} />}
    </div>
  )
}

function Panel({ id, onClose, unread }: { id: string; onClose: () => void; unread: number }) {
  const inbox = useInbox()
  const markRead = useMarkRead()
  const items = inbox.data?.pages[0]?.items.slice(0, 8) ?? []
  return (
    <div
      id={id}
      role="dialog"
      aria-label="Notifications"
      className="absolute right-0 z-30 mt-2 w-[min(24rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-border bg-surface shadow-card"
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <h2 className="text-sm font-semibold">Notifications</h2>
        {unread > 0 && (
          <button type="button" className="text-xs font-medium text-accent hover:underline" disabled={markRead.isPending} onClick={() => markRead.mutate(undefined)}>
            Mark all read
          </button>
        )}
      </header>
      {inbox.isPending ? (
        <p className="px-4 py-6 text-sm text-muted">Loading…</p>
      ) : !items.length ? (
        <p className="px-4 py-6 text-sm text-muted">Nothing needs your attention.</p>
      ) : (
        <ul className="max-h-96 divide-y divide-border overflow-y-auto">
          {items.map((item) => (
            <InboxItemRow key={item.id} item={item} onOpen={onClose} compact />
          ))}
        </ul>
      )}
      <footer className="border-t border-border px-4 py-2.5 text-center">
        <Link to="/inbox" onClick={onClose} className="text-xs font-medium text-accent hover:underline">
          See all notifications
        </Link>
      </footer>
    </div>
  )
}
