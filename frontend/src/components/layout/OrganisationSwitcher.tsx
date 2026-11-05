import { ArrowLeftRight } from "lucide-react"
import { useId } from "react"

import { useCurrentTenant, useMspOverview } from "@/api/queries"
import { humanize } from "@/lib/format"
import { useActiveOrganisation } from "@/lib/organisation"
import { useSwitchOrganisation } from "@/lib/useSwitchOrganisation"

/** For a service provider's people: which organisation they are working in. Others see their organisation's name. */
export function OrganisationSwitcher() {
  const overview = useMspOverview()
  const tenant = useCurrentTenant()
  const active = useActiveOrganisation()
  const switchTo = useSwitchOrganisation()
  const id = useId()
  const msp = overview.data?.msp ? overview.data : null

  if (!msp) {
    if (!tenant.data) return null
    return (
      <p className="truncate px-2 text-xs text-subtle" title={tenant.data.name}>
        {tenant.data.name}
      </p>
    )
  }
  return (
    <div className="px-2">
      <label htmlFor={id} className="sr-only">
        Organisation
      </label>
      <select
        id={id}
        value={active ?? ""}
        onChange={(event) => switchTo(event.target.value || null)}
        className="w-full truncate rounded-lg border border-border bg-surface px-2 py-1.5 text-xs"
      >
        <option value="">{msp.organisation} (yours)</option>
        {msp.clients.map((client) => (
          <option key={client.id} value={client.id}>
            {client.name}
            {client.urgent_alerts ? ` (${client.urgent_alerts} urgent)` : ""}
          </option>
        ))}
      </select>
    </div>
  )
}

/** While working in a client: whose data this is, and the way back. */
export function ActingBanner() {
  const overview = useMspOverview()
  const active = useActiveOrganisation()
  const switchTo = useSwitchOrganisation()
  const msp = overview.data?.msp ? overview.data : null
  if (!msp || !active) return null
  const client = msp.clients.find((item) => item.id === active)
  return (
    <div className="mb-6 flex flex-wrap items-center gap-3 rounded-xl border border-accent/30 bg-accent/10 px-4 py-2.5 text-sm">
      <ArrowLeftRight className="size-4 shrink-0 text-accent" aria-hidden />
      <span className="min-w-0 flex-1">
        Working in <strong>{client?.name ?? "a client organisation"}</strong> for {msp.organisation}
        {msp.role_in_clients ? `, as ${msp.role_in_clients === "viewer" ? "read-only" : humanize(msp.role_in_clients).toLowerCase()}` : ""}.
        Everything you do is in its audit log.
      </span>
      <button type="button" className="text-sm font-medium text-accent hover:underline" onClick={() => switchTo(null, "/clients")}>
        Back to {msp.organisation}
      </button>
    </div>
  )
}
