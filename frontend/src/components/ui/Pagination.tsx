import { ChevronLeft, ChevronRight } from "lucide-react"

import { Button } from "./Button"

export function Pagination({
  page,
  hasMore,
  onPage,
  fetching,
}: {
  page: number
  hasMore: boolean
  onPage: (page: number) => void
  fetching?: boolean
}) {
  if (page === 0 && !hasMore) return null
  return (
    <nav className="flex items-center justify-between border-t border-border px-5 py-3" aria-label="Pagination">
      <span className="text-xs text-muted">Page {page + 1}</span>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => onPage(page - 1)} disabled={page === 0 || fetching}>
          <ChevronLeft className="size-4" aria-hidden /> Previous
        </Button>
        <Button size="sm" onClick={() => onPage(page + 1)} disabled={!hasMore || fetching}>
          Next <ChevronRight className="size-4" aria-hidden />
        </Button>
      </div>
    </nav>
  )
}
