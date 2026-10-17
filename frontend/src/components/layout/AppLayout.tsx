import {
  Activity,
  FlaskConical,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  ScrollText,
  Server,
  ShieldAlert,
  UserRound,
  Users,
  X,
} from "lucide-react"
import { useEffect, useState } from "react"
import { Link, NavLink, Outlet, useLocation } from "react-router"

import { useAlertSummary } from "@/api/queries"
import { useAuth, useIsAdmin, useUser } from "@/auth/context"
import { cx } from "@/lib/cx"
import { humanize } from "@/lib/format"

import { Logo } from "./Logo"
import { SystemStatus } from "./SystemStatus"
import { ThemeSwitcher } from "./ThemeSwitcher"

const NAVIGATION = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/alerts", label: "Alerts", icon: ShieldAlert },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/rules", label: "Detection rules", icon: ListChecks },
  { to: "/simulations", label: "Simulations", icon: FlaskConical },
] as const

const ADMIN_NAVIGATION = [
  { to: "/users", label: "Users", icon: Users },
  { to: "/api-keys", label: "API keys", icon: KeyRound },
  { to: "/audit-log", label: "Audit log", icon: ScrollText },
] as const

function OpenAlertCount() {
  const { data } = useAlertSummary()
  const count = (data?.by_status.open ?? 0) + (data?.by_status.in_progress ?? 0)
  if (!count) return null
  return (
    <span className="ml-auto rounded-full bg-danger/15 px-1.5 py-0.5 text-[11px] font-semibold text-danger tabular-nums">
      {count > 99 ? "99+" : count}
      <span className="sr-only"> open</span>
    </span>
  )
}

function Navigation({ onNavigate }: { onNavigate?: () => void }) {
  const isAdmin = useIsAdmin()
  const items = isAdmin ? [...NAVIGATION, ...ADMIN_NAVIGATION] : NAVIGATION
  return (
    <nav aria-label="Main" className="space-y-0.5">
      {items.map(({ to, label, icon: Icon, ...rest }) => (
        <NavLink
          key={to}
          to={to}
          end={"end" in rest}
          onClick={onNavigate}
          className={({ isActive }) =>
            cx(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive ? "bg-accent/12 text-fg" : "text-muted hover:bg-surface-2 hover:text-fg",
            )
          }
        >
          {({ isActive }) => (
            <>
              <Icon className={cx("size-4", isActive ? "text-accent" : "text-subtle")} aria-hidden />
              {label}
              {to === "/alerts" && <OpenAlertCount />}
            </>
          )}
        </NavLink>
      ))}
    </nav>
  )
}

function UserPanel({ onNavigate }: { onNavigate?: () => void }) {
  const user = useUser()
  const { logout } = useAuth()
  const name = [user.firstName, user.lastName].filter(Boolean).join(" ") || user.username
  const initials = name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase()

  return (
    <div className="rounded-xl border border-border bg-surface-2/60 p-3">
      <div className="flex items-center gap-3">
        <div className="grid size-9 shrink-0 place-items-center rounded-full bg-accent/15 text-xs font-semibold text-accent">
          {initials}
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{name}</p>
          <p className="truncate text-xs text-subtle">{humanize(user.role)}</p>
        </div>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-1.5">
        <Link
          to="/profile"
          onClick={onNavigate}
          className="flex items-center justify-center gap-1.5 rounded-md py-1.5 text-xs text-muted hover:bg-surface-3 hover:text-fg"
        >
          <UserRound className="size-3.5" aria-hidden /> Profile
        </Link>
        <button
          type="button"
          onClick={() => logout()}
          className="flex items-center justify-center gap-1.5 rounded-md py-1.5 text-xs text-muted hover:bg-surface-3 hover:text-fg"
        >
          <LogOut className="size-3.5" aria-hidden /> Sign out
        </button>
      </div>
    </div>
  )
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col gap-6 p-4">
      <Link to="/" onClick={onNavigate} className="px-2 pt-1" aria-label="UTDRS overview">
        <Logo />
      </Link>
      <Navigation onNavigate={onNavigate} />
      <div className="mt-auto space-y-3">
        <ThemeSwitcher />
        <UserPanel onNavigate={onNavigate} />
      </div>
    </div>
  )
}

export function AppLayout() {
  const [menuOpen, setMenuOpen] = useState(false)
  const location = useLocation()

  // Move focus to the new page after navigation, as a full page load would.
  useEffect(() => {
    document.getElementById("main")?.focus({ preventScroll: true })
  }, [location.pathname])

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[248px_1fr]">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-accent px-3 py-2 text-accent-fg focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Skip to content
      </a>

      <aside className="sticky top-0 hidden h-dvh border-r border-border bg-surface/60 lg:block">
        <SidebarContent />
      </aside>

      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Menu">
          <div className="absolute inset-0 bg-black/50" onClick={() => setMenuOpen(false)} aria-hidden />
          <aside className="absolute inset-y-0 left-0 w-72 max-w-[85vw] border-r border-border bg-surface">
            <button
              type="button"
              onClick={() => setMenuOpen(false)}
              className="absolute top-4 right-3 rounded-md p-1.5 text-muted hover:bg-surface-2"
              aria-label="Close menu"
            >
              <X className="size-4" />
            </button>
            <SidebarContent onNavigate={() => setMenuOpen(false)} />
          </aside>
        </div>
      )}

      <div className="min-w-0">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-bg/80 px-4 backdrop-blur sm:px-6 lg:px-8">
          <button
            type="button"
            onClick={() => setMenuOpen(true)}
            className="-ml-1 rounded-md p-1.5 text-muted hover:bg-surface-2 lg:hidden"
            aria-label="Open menu"
          >
            <Menu className="size-5" />
          </button>
          <Link to="/" className="lg:hidden" aria-label="UTDRS overview">
            <Logo compact />
          </Link>
          <div className="ml-auto">
            <SystemStatus />
          </div>
        </header>
        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-7xl px-4 py-6 outline-none sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
