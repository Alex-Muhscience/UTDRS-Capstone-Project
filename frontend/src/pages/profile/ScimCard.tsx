import { Copy } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { gatewayUrl } from "@/api/client"
import { useNewScimToken, useRevokeScimToken, useRoles, useScimGroups, useScimStatus, useSetScimGroupRole } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Field"
import { formatDateTime, formatRelative } from "@/lib/format"

/** SCIM provisioning: the organisation's identity provider manages its UTDRS accounts (administrators). */
export function ScimCard() {
  const status = useScimStatus()
  const make = useNewScimToken()
  const revoke = useRevokeScimToken()
  const [token, setToken] = useState<string | null>(null)
  const baseUrl = `${gatewayUrl()}/api/v1/scim/v2`

  function copy(text: string) {
    void navigator.clipboard?.writeText(text).then(() => toast.success("Copied"))
  }

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          Provisioning (SCIM)
          {status.data?.enabled ? <Badge tone="success">On</Badge> : <Badge>Off</Badge>}
        </span>
      }
      description="Your identity provider (Microsoft Entra ID, Okta, ...) creates, updates and deactivates people's accounts here. Deactivating someone signs them out at once."
    >
      <div className="space-y-3 text-sm">
        <p>
          <span className="block text-xs text-muted">Tenant URL (SCIM base URL)</span>
          <span className="flex items-center gap-2">
            <code className="break-all text-xs">{baseUrl}</code>
            <Button size="sm" variant="ghost" aria-label="Copy the SCIM URL" onClick={() => copy(baseUrl)}>
              <Copy className="size-3.5" aria-hidden />
            </Button>
          </span>
        </p>
        {status.data?.enabled && !token && (
          <p className="text-muted">
            Token made <span title={formatDateTime(status.data.created_at)}>{formatRelative(status.data.created_at)}</span>
            {status.data.last_used_at ? `, last used ${formatRelative(status.data.last_used_at)}` : ", not used yet"}.
          </p>
        )}
        {token && (
          <div className="rounded-lg border border-warning/40 bg-warning/10 p-3" role="status">
            <span className="block text-xs font-medium">Secret token: copy it into your identity provider now. It is not shown again.</span>
            <span className="mt-1 flex items-center gap-2">
              <code className="break-all text-xs" aria-label="SCIM token">
                {token}
              </code>
              <Button size="sm" variant="ghost" aria-label="Copy the token" onClick={() => copy(token)}>
                <Copy className="size-3.5" aria-hidden />
              </Button>
            </span>
          </div>
        )}
        <p className="text-xs text-muted">
          Accounts it creates are analysts and sign in with single sign-on or a passkey. Their roles can follow the groups it manages (below). It
          never deactivates or demotes your last administrator.
        </p>
        {status.data?.enabled && <ScimGroups />}
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            loading={make.isPending}
            onClick={() => make.mutate(undefined, { onSuccess: (made) => setToken(made.token), onError: (error) => toast.error(error.message) })}
          >
            {status.data?.enabled ? "Replace the token" : "Turn on and make a token"}
          </Button>
          {status.data?.enabled && (
            <Button
              size="sm"
              variant="danger"
              loading={revoke.isPending}
              onClick={() =>
                revoke.mutate(undefined, {
                  onSuccess: () => {
                    setToken(null)
                    toast.success("SCIM turned off")
                  },
                  onError: (error) => toast.error(error.message),
                })
              }
            >
              Turn off
            </Button>
          )}
        </div>
      </div>
    </Card>
  )
}

const GROUP_ROLES = [
  { value: "", label: "Nothing" },
  { value: "admin", label: "Administrator" },
  { value: "analyst", label: "Analyst" },
  { value: "viewer", label: "Read-only" },
]

/** What each group from the identity provider gives its members in UTDRS. */
function ScimGroups() {
  const groups = useScimGroups()
  const roles = useRoles()
  const setRole = useSetScimGroupRole()
  const options = [...GROUP_ROLES, ...(roles.data ?? []).map((role) => ({ value: `custom:${role.id}`, label: role.name }))]
  if (!groups.data?.length) {
    return <p className="text-xs text-muted">No groups yet. When your identity provider pushes groups, choose here what each gives its members.</p>
  }
  return (
    <div className="space-y-2">
      <p className="text-xs font-medium">Groups and the roles they give</p>
      <p className="text-xs text-muted">
        Members get the most powerful role of their groups. Someone whose role came from groups becomes read-only when they leave them all; roles you
        set by hand stay unless a group gives one.
      </p>
      <ul className="divide-y divide-border rounded-lg border border-border" aria-label="SCIM groups">
        {groups.data.map((group) => (
          <li key={group.id} className="flex flex-wrap items-center gap-3 px-3 py-2">
            <span className="min-w-0 flex-1">
              <span className="block font-medium">{group.display_name}</span>
              <span className="block text-xs text-muted">{group.members === 1 ? "1 person" : `${group.members} people`}</span>
            </span>
            <Select
              aria-label={`Role from ${group.display_name}`}
              className="h-8 w-48 text-xs"
              value={group.role === "custom" ? `custom:${group.custom_role_id}` : (group.role ?? "")}
              options={options}
              disabled={setRole.isPending}
              onChange={(event) => {
                const value = event.target.value
                const custom = value.startsWith("custom:")
                setRole.mutate(
                  {
                    groupId: group.id,
                    role: custom ? "custom" : ((value || null) as "admin" | "analyst" | "viewer" | null),
                    custom_role_id: custom ? value.slice("custom:".length) : null,
                  },
                  {
                    onSuccess: () => toast.success(`${group.display_name}: ${options.find((option) => option.value === value)?.label ?? "updated"}`),
                    onError: (error) => toast.error(error.message),
                  },
                )
              }}
            />
          </li>
        ))}
      </ul>
    </div>
  )
}
