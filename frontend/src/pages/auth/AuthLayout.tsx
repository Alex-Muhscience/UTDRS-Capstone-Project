import { Activity, ListChecks, ShieldAlert } from "lucide-react"
import type { ReactNode } from "react"

import { Logo } from "@/components/layout/Logo"

const POINTS = [
  { icon: Activity, title: "Every event analysed", text: "Events sent to the gateway go through the core engine's rule, anomaly and ML detectors." },
  { icon: ShieldAlert, title: "Alerts you can act on", text: "Each alert links to the event that raised it and the MITRE ATT&CK techniques it matches." },
  { icon: ListChecks, title: "Explainable by design", text: "Rule, anomaly and ML detections sit side by side, so every alert can be traced to what raised it." },
]

export function AuthLayout({ title, subtitle, children }: { title: string; subtitle: ReactNode; children: ReactNode }) {
  return (
    <div className="grid min-h-dvh lg:grid-cols-[1.1fr_1fr]">
      <aside className="relative hidden overflow-hidden border-r border-border bg-surface lg:flex lg:flex-col lg:justify-between lg:p-12">
        <div
          className="pointer-events-none absolute inset-0 opacity-60"
          style={{
            background:
              "radial-gradient(600px 400px at 15% 10%, color-mix(in oklab, var(--accent) 22%, transparent), transparent 70%), radial-gradient(500px 360px at 90% 90%, color-mix(in oklab, var(--sev-critical) 12%, transparent), transparent 70%)",
          }}
          aria-hidden
        />
        <div className="relative">
          <Logo />
        </div>
        <div className="relative max-w-md">
          <h2 className="text-3xl font-semibold tracking-tight text-balance">
            Threat detection and response for teams without a security operations centre.
          </h2>
          <ul className="mt-10 space-y-6">
            {POINTS.map(({ icon: Icon, title: pointTitle, text }) => (
              <li key={pointTitle} className="flex gap-4">
                <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-border bg-surface-2 text-accent">
                  <Icon className="size-4" aria-hidden />
                </span>
                <span>
                  <span className="block text-sm font-medium">{pointTitle}</span>
                  <span className="mt-0.5 block text-sm text-muted">{text}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-subtle">Top 5 finalist · Mozilla Responsible Computing Challenge</p>
      </aside>

      <main className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Logo />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1.5 text-sm text-muted">{subtitle}</p>
          <div className="mt-8">{children}</div>
        </div>
      </main>
    </div>
  )
}
