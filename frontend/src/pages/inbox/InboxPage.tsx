import { useState } from "react"

import { useInbox, useMarkRead, useUnreadCount } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { cx } from "@/lib/cx"

import { InboxItemRow } from "./InboxItemRow"

export function InboxPage() {
  const [unreadOnly, setUnreadOnly] = useState(false)
  const inbox = useInbox(unreadOnly)
  const unread = useUnreadCount()
  const markRead = useMarkRead()
  const items = inbox.data?.pages.flatMap((page) => page.items) ?? []
  const count = unread.data?.unread ?? 0

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifications"
        description="What needs your attention: serious alerts and cases, decisions waiting for you, failed actions, and work assigned to you. Kept for 90 days."
        actions={
          <Button disabled={!count || markRead.isPending} onClick={() => markRead.mutate(undefined)}>
            Mark all read
          </Button>
        }
      />
      <div className="flex gap-2" role="group" aria-label="Show">
        {[
          [false, "All"],
          [true, `Unread${count ? ` (${count})` : ""}`],
        ].map(([value, label]) => (
          <button
            key={String(value)}
            type="button"
            aria-pressed={unreadOnly === value}
            onClick={() => setUnreadOnly(value as boolean)}
            className={cx(
              "rounded-full border px-3 py-1 text-xs font-medium",
              unreadOnly === value ? "border-accent bg-accent/10 text-fg" : "border-border text-muted hover:text-fg",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <Card bodyClassName="p-0">
        {inbox.isPending ? (
          <SkeletonRows rows={4} columns={2} />
        ) : inbox.isError ? (
          <ErrorState error={inbox.error} onRetry={() => void inbox.refetch()} />
        ) : !items.length ? (
          <EmptyState title={unreadOnly ? "Nothing unread" : "No notifications yet"}>Serious alerts, decisions and assignments will appear here.</EmptyState>
        ) : (
          <ul className="divide-y divide-border" aria-label="Notifications">
            {items.map((item) => (
              <InboxItemRow key={item.id} item={item} />
            ))}
          </ul>
        )}
      </Card>
      {inbox.hasNextPage && (
        <div className="text-center">
          <Button loading={inbox.isFetchingNextPage} onClick={() => void inbox.fetchNextPage()}>
            Show older
          </Button>
        </div>
      )}
    </div>
  )
}
