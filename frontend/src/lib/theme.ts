import { useCallback, useEffect, useState } from "react"

export type Theme = "system" | "light" | "dark"

const KEY = "utdrs-theme"

function readTheme(): Theme {
  try {
    const value = localStorage.getItem(KEY)
    return value === "light" || value === "dark" ? value : "system"
  } catch {
    return "system"
  }
}

/** The chosen theme, applied as <html data-theme>; "system" follows the OS setting. */
export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(readTheme)

  useEffect(() => {
    const root = document.documentElement
    if (theme === "system") delete root.dataset.theme
    else root.dataset.theme = theme
    try {
      if (theme === "system") localStorage.removeItem(KEY)
      else localStorage.setItem(KEY, theme)
    } catch {
      // Not persisted; the choice still applies until reload.
    }
  }, [theme])

  const setTheme = useCallback((next: Theme) => setThemeState(next), [])
  return { theme, setTheme }
}
