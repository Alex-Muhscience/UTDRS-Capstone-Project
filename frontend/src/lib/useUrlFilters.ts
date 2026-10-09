import { useCallback } from "react"
import { useSearchParams } from "react-router"

/**
 * List filters kept in the URL, so a filtered view can be bookmarked or shared.
 * Changing a filter returns to the first page.
 */
export function useUrlFilters<K extends string>(keys: readonly K[]) {
  const [params, setParams] = useSearchParams()

  const filters = Object.fromEntries(keys.map((key) => [key, params.get(key) ?? ""])) as Record<K, string>
  const page = Math.max(0, Number(params.get("page") ?? 1) - 1) || 0

  const setFilter = useCallback(
    (key: K, value: string) =>
      setParams(
        (current) => {
          const next = new URLSearchParams(current)
          if (value) next.set(key, value)
          else next.delete(key)
          next.delete("page")
          return next
        },
        { replace: true },
      ),
    [setParams],
  )

  const setPage = useCallback(
    (nextPage: number) =>
      setParams((current) => {
        const next = new URLSearchParams(current)
        if (nextPage > 0) next.set("page", String(nextPage + 1))
        else next.delete("page")
        return next
      }),
    [setParams],
  )

  return { filters, page, setFilter, setPage }
}
