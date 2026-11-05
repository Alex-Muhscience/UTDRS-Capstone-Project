import { Copy } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { gatewayUrl } from "@/api/client"
import { useNewScimToken, useRevokeScimToken, useScimStatus } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
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
          Accounts it creates are analysts and sign in with single sign-on or a passkey. It never changes roles, and never deactivates your last
          administrator.
        </p>
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
