import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import { useConnectGoogleWorkspace, useDisconnectGoogleWorkspace, useGoogleWorkspace, usePollGoogleWorkspace } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { DescriptionList } from "@/components/ui/DescriptionList"
import { Field, Input, Textarea } from "@/components/ui/Field"
import { ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime, formatRelative } from "@/lib/format"

const SOURCES: Record<string, string> = {
  login: "Sign-ins",
  admin: "Administrator actions",
  token: "App authorisations",
  user_accounts: "Account settings",
  drive: "Drive sharing",
  signing_in: "Signing in",
}

/** Google Workspace: sign-ins, administrator actions and app authorisations, through a service account. */
export function GoogleWorkspaceCard() {
  const status = useGoogleWorkspace()
  const connect = useConnectGoogleWorkspace()
  const poll = usePollGoogleWorkspace()
  const disconnect = useDisconnectGoogleWorkspace()
  const [error, setError] = useState<string | null>(null)

  if (status.isPending) return <SkeletonRows rows={3} columns={2} />
  if (status.isError) return <ErrorState error={status.error} onRetry={() => void status.refetch()} />
  const data = status.data

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const file = form.get("key_file")
    const pasted = String(form.get("key") ?? "").trim()
    const key = file instanceof File && file.size > 0 ? await file.text() : pasted
    if (!key) {
      setError("Choose the service account's JSON key file, or paste it.")
      return
    }
    setError(null)
    connect.mutate(
      { service_account_key: key, admin_email: String(form.get("admin_email") ?? "").trim() },
      { onSuccess: (connected) => toast.success(`Google Workspace connected for ${connected.domain}`), onError: (caught) => setError(caught.message) },
    )
  }

  const errors = Object.entries(data.errors ?? {})
  const counts = data.last_poll ?? {}
  return (
    <Card
      className="xl:col-span-2"
      title={
        <span className="flex items-center gap-2">
          Google Workspace
          {data.connected ? (
            <Badge tone={data.status === "error" ? "warning" : "success"}>{data.status === "error" ? "Needs attention" : "Connected"}</Badge>
          ) : (
            <Badge>Not connected</Badge>
          )}
        </span>
      }
      description="Sign-ins, suspicious sign-ins, administrator actions, app authorisations, Drive sharing and mail forwarding, every few minutes; and account actions."
    >
      {data.connected ? (
        <div className="space-y-4">
          <DescriptionList
            items={[
              ["Domain", data.domain],
              ["Acting as", data.admin_email],
              ["Service account", <span key="sa" className="font-mono text-xs">{data.client_email}</span>],
              ["Connected", formatDateTime(data.connected_at)],
              [
                "Last fetched",
                data.last_poll_at
                  ? `${formatRelative(data.last_poll_at)}: ${counts.login ?? 0} sign-ins, ${counts.admin ?? 0} administrator actions, ${counts.token ?? 0} app authorisations, ${counts.drive ?? 0} sharing changes, ${counts.user_accounts ?? 0} account settings`
                  : "Not yet",
              ],
              ["Last data received", data.last_data_at ? formatRelative(data.last_data_at) : "Nothing yet"],
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
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              loading={poll.isPending}
              onClick={() => poll.mutate(undefined, { onSuccess: () => toast.success("Fetched"), onError: (caught) => toast.error(caught.message) })}
            >
              Fetch now
            </Button>
            <Button
              size="sm"
              variant="danger"
              loading={disconnect.isPending}
              onClick={() => disconnect.mutate(undefined, { onSuccess: () => toast.success("Google Workspace disconnected"), onError: (caught) => toast.error(caught.message) })}
            >
              Disconnect
            </Button>
          </div>
        </div>
      ) : (
        <form onSubmit={(event) => void onSubmit(event)} className="space-y-3">
          <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
            <li>In Google Cloud, create a service account and a JSON key for it, and turn on the Admin SDK API.</li>
            <li>
              In the Google Admin console (Security → API controls → Domain-wide delegation), add the service account's client id with these scopes:
              <code className="mt-1 block break-all text-xs text-fg">{data.scopes.join(",")}</code>
            </li>
            <li>Give the key and a Workspace administrator for UTDRS to act as. The key is kept encrypted and never shown again.</li>
          </ol>
          {!data.encryption_available && <p className="text-sm text-warning">The gateway needs ENCRYPTION_KEY set to keep the key.</p>}
          <Field label="Service account key (JSON file)">
            {(id) => <Input id={id} name="key_file" type="file" accept="application/json,.json" />}
          </Field>
          <Field label="Or paste the key">
            {(id) => <Textarea id={id} name="key" rows={3} className="font-mono text-xs" placeholder='{"type": "service_account", ...}' />}
          </Field>
          <Field label="Administrator to act as" required>
            {(id) => <Input id={id} name="admin_email" type="email" required placeholder="it-admin@yourcompany.com" />}
          </Field>
          {error && (
            <p className="text-sm text-danger" role="alert">
              {error}
            </p>
          )}
          <Button type="submit" variant="primary" loading={connect.isPending} disabled={!data.encryption_available}>
            Connect Google Workspace
          </Button>
        </form>
      )}
    </Card>
  )
}
