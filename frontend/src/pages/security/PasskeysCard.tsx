import { KeyRound, Trash2 } from "lucide-react"
import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import { useAddPasskey, usePasskeys, useRemovePasskey } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input } from "@/components/ui/Field"
import { formatDateTime, formatRelative } from "@/lib/format"
import { passkeyErrorMessage, passkeysSupported } from "@/lib/webauthn"

/** Signing in with this device's fingerprint, face or PIN instead of a password. */
export function PasskeysCard() {
  const passkeys = usePasskeys()
  const add = useAddPasskey()
  const remove = useRemovePasskey()
  const [error, setError] = useState<string | null>(null)

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const name = String(new FormData(form).get("name") ?? "").trim() || "Passkey"
    setError(null)
    add.mutate(name, {
      onSuccess: (added) => {
        toast.success(`Passkey "${added.name}" added`)
        form.reset()
      },
      onError: (caught) => setError(passkeyErrorMessage(caught)),
    })
  }

  return (
    <Card
      title="Passkeys"
      description="Sign in with your device's fingerprint, face or PIN. A passkey only works on this site, so it cannot be phished, and counts as multi-factor."
    >
      {passkeys.data && passkeys.data.length > 0 && (
        <ul className="mb-3 divide-y divide-border" aria-label="Your passkeys">
          {passkeys.data.map((passkey) => (
            <li key={passkey.id} className="flex items-center gap-2 py-2 text-sm">
              <KeyRound className="size-4 shrink-0 text-muted" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2 font-medium">
                  {passkey.name}
                  {passkey.backed_up && <Badge>Synced</Badge>}
                </span>
                <span className="block text-xs text-muted" title={formatDateTime(passkey.created_at)}>
                  Added {formatRelative(passkey.created_at)}
                  {passkey.last_used_at ? `, last used ${formatRelative(passkey.last_used_at)}` : ", not used yet"}
                </span>
              </span>
              <Button
                size="sm"
                variant="ghost"
                aria-label={`Remove ${passkey.name}`}
                disabled={remove.isPending}
                onClick={() =>
                  remove.mutate(passkey.id, {
                    onSuccess: () => toast.success(`Passkey "${passkey.name}" removed`),
                    onError: (caught) => toast.error(caught.message),
                  })
                }
              >
                <Trash2 className="size-3.5" aria-hidden />
              </Button>
            </li>
          ))}
        </ul>
      )}
      {passkeysSupported() ? (
        <form onSubmit={onSubmit} className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <Field label="Name" className="flex-1" hint="Which device or password manager it is on.">
            {(id, describedBy) => <Input id={id} name="name" maxLength={60} placeholder="Work laptop" aria-describedby={describedBy} />}
          </Field>
          <Button type="submit" loading={add.isPending}>
            <KeyRound className="size-4" aria-hidden /> Add a passkey
          </Button>
        </form>
      ) : (
        <p className="text-sm text-muted">This browser cannot create passkeys.</p>
      )}
      {error && (
        <p className="mt-2 text-sm text-danger" role="alert">
          {error}
        </p>
      )}
    </Card>
  )
}
