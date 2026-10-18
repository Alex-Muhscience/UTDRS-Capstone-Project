import { CheckCircle2, XCircle } from "lucide-react"
import { toast } from "sonner"

import type { Microsoft365 } from "@/api/client"
import { useCheckMicrosoft365, useConnectOwnApp, useConsentUrl, useDisconnectMicrosoft365, useMicrosoft365, usePollMicrosoft365 } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime, formatRelative } from "@/lib/format"

const SOURCES: Record<string, string> = { signins: "sign-ins", audits: "audit records", alerts: "Defender alerts", signing_in: "signing in" }

export const CONSENT_PATH = "/connectors/microsoft-365/consented"

function Connect({ status }: { status: Microsoft365 }) {
  const consent = useConsentUrl()
  const connect = useConnectOwnApp()

  return (
    <div className="space-y-5">
      {status.consent_available && (
        <div className="space-y-2">
          <p className="text-sm">A Microsoft 365 administrator in your organisation approves UTDRS's access. Nothing secret is stored.</p>
          <Button
            variant="primary"
            loading={consent.isPending}
            onClick={() =>
              consent.mutate(`${window.location.origin}${CONSENT_PATH}`, {
                onSuccess: ({ url }) => window.location.assign(url),
                onError: (error) => toast.error(error.message),
              })
            }
          >
            Connect with Microsoft
          </Button>
        </div>
      )}
      <form
        className="space-y-3 border-t border-border pt-4 first:border-0 first:pt-0"
        onSubmit={(event) => {
          event.preventDefault()
          const data = new FormData(event.currentTarget)
          const text = (name: string) => String(data.get(name) ?? "").trim()
          connect.mutate(
            { azure_tenant_id: text("tenant"), client_id: text("client_id"), client_secret: String(data.get("client_secret") ?? "") },
            { onSuccess: () => toast.success("Microsoft 365 connected"), onError: (error) => toast.error(error.message) },
          )
        }}
      >
        <div>
          <p className="text-sm font-medium">{status.consent_available ? "Or use your own app registration" : "Connect with your own app registration"}</p>
          <p className="text-xs text-muted">
            In the Microsoft Entra admin centre, register an application, give it the application permissions listed here with admin consent, and create a client secret.
          </p>
        </div>
        {!status.encryption_available && (
          <p className="rounded-lg bg-warning/10 px-3 py-2 text-sm text-warning">The gateway has no ENCRYPTION_KEY, so it cannot store a client secret yet.</p>
        )}
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Directory (tenant) ID" required>
            {(id) => <Input id={id} name="tenant" required autoComplete="off" placeholder="00000000-0000-0000-0000-000000000000" />}
          </Field>
          <Field label="Application (client) ID" required>
            {(id) => <Input id={id} name="client_id" required autoComplete="off" />}
          </Field>
          <Field label="Client secret" required>
            {(id) => <Input id={id} name="client_secret" type="password" required autoComplete="off" />}
          </Field>
        </div>
        <Button type="submit" loading={connect.isPending} disabled={!status.encryption_available}>
          Connect
        </Button>
      </form>
    </div>
  )
}

function Connected({ status }: { status: Microsoft365 }) {
  const check = useCheckMicrosoft365()
  const poll = usePollMicrosoft365()
  const disconnect = useDisconnectMicrosoft365()
  const errors = Object.entries(status.errors ?? {})
  const counts = status.last_poll ?? {}

  return (
    <div className="space-y-4">
      <DescriptionList
        items={[
          ["Organisation", status.organisation_name ?? "—"],
          ["Tenant", <span key="tenant" className="font-mono text-xs">{status.azure_tenant_id}</span>],
          ["Connected", `${status.mode === "consent" ? "By admin consent" : "With your app registration"}, ${formatDateTime(status.connected_at)}`],
          [
            "Last fetched",
            status.last_poll_at
              ? `${formatRelative(status.last_poll_at)}: ${counts.signins ?? 0} sign-ins, ${counts.audits ?? 0} audit records, ${counts.alerts ?? 0} Defender alerts`
              : "Not yet",
          ],
        ]}
      />
      {errors.length > 0 && (
        <ul className="space-y-1 rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">
          {errors.map(([source, message]) => (
            <li key={source}>
              {SOURCES[source] ?? source}: {message}
            </li>
          ))}
        </ul>
      )}
      {status.checks?.length ? (
        <ul className="space-y-1 text-sm" aria-label="What UTDRS can read">
          {status.checks.map((item) => (
            <li key={item.name} className="flex items-start gap-2">
              {item.ok ? <CheckCircle2 className="mt-0.5 size-4 text-success" aria-label="Works" /> : <XCircle className="mt-0.5 size-4 text-danger" aria-label="Does not work" />}
              <span>
                <span className="font-medium">{item.name}</span> <span className="text-muted">{item.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" loading={poll.isPending} onClick={() => poll.mutate(undefined, { onSuccess: () => toast.success("Fetched"), onError: (error) => toast.error(error.message) })}>
          Fetch now
        </Button>
        <Button size="sm" loading={check.isPending} onClick={() => check.mutate(undefined, { onError: (error) => toast.error(error.message) })}>
          Check permissions
        </Button>
        <Button
          size="sm"
          loading={disconnect.isPending}
          onClick={() => disconnect.mutate(undefined, { onSuccess: () => toast.success("Microsoft 365 disconnected"), onError: (error) => toast.error(error.message) })}
        >
          Disconnect
        </Button>
      </div>
    </div>
  )
}

export function ConnectorsPage() {
  const m365 = useMicrosoft365()

  return (
    <>
      <PageHeader
        title="Connectors"
        description="The services UTDRS watches and acts through. Connected services feed detection, and let response actions and playbooks act for you."
      />
      {m365.isPending ? (
        <SkeletonRows rows={4} columns={2} />
      ) : m365.isError ? (
        <ErrorState error={m365.error} onRetry={() => void m365.refetch()} />
      ) : (
        <div className="grid gap-4 xl:grid-cols-3">
          <Card
            className="xl:col-span-2"
            title={
              <span className="flex items-center gap-2">
                Microsoft 365
                {m365.data.connected ? (
                  <Badge tone={m365.data.status === "error" ? "warning" : "success"}>{m365.data.status === "error" ? "Needs attention" : "Connected"}</Badge>
                ) : (
                  <Badge>Not connected</Badge>
                )}
              </span>
            }
            description="Entra ID sign-ins and audit logs, and Microsoft Defender alerts, every few minutes; and account and email actions."
          >
            {m365.data.connected ? <Connected status={m365.data} /> : <Connect status={m365.data} />}
          </Card>
          <Card title="Permissions UTDRS asks for" description="Application permissions in Microsoft Graph, granted by a Microsoft 365 administrator.">
            <ul className="space-y-2 text-sm">
              {m365.data.permissions.map((permission) => (
                <li key={permission.name}>
                  <span className="font-mono text-xs">{permission.name}</span>
                  <span className="block text-muted">To {permission.used_for}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}
    </>
  )
}
