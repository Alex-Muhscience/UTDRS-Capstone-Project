import { Monitor, Moon, Sun } from "lucide-react"

import { cx } from "@/lib/cx"
import { useTheme, type Theme } from "@/lib/theme"

const OPTIONS: Array<{ value: Theme; label: string; icon: typeof Sun }> = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
]

export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme()
  return (
    <div role="radiogroup" aria-label="Theme" className="grid grid-cols-3 gap-1 rounded-lg border border-border bg-surface-2/60 p-1">
      {OPTIONS.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={theme === value}
          onClick={() => setTheme(value)}
          title={label}
          className={cx(
            "flex items-center justify-center gap-1.5 rounded-md py-1 text-xs transition-colors",
            theme === value ? "bg-surface text-fg shadow-sm" : "text-subtle hover:text-fg",
          )}
        >
          <Icon className="size-3.5" aria-hidden />
          <span className="sr-only sm:not-sr-only">{label}</span>
        </button>
      ))}
    </div>
  )
}
