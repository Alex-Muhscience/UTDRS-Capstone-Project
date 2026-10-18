import { useState } from "react"
import { toast } from "sonner"

import { useConfirmMfa, useStartMfa } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"

import { QrCode } from "./QrCode"

/** Recovery codes, shown once, with a way to copy them. */
export function RecoveryCodesList({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  return (
    <div className="space-y-3">
      <p className="text-sm">
        Keep these recovery codes somewhere safe, such as a password manager. Each signs you in once if your phone is not at hand. They are not shown again.
      </p>
      <ul aria-label="Recovery codes" className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-lg bg-surface-2 p-3 font-mono text-sm whitespace-nowrap">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex gap-2">
        <Button
          size="sm"
          onClick={() => {
            void navigator.clipboard?.writeText(codes.join("\n"))
            toast.success("Copied")
          }}
        >
          Copy
        </Button>
        <Button size="sm" variant="primary" onClick={onDone}>
          I have saved them
        </Button>
      </div>
    </div>
  )
}

/** Setting up an authenticator app: scan, confirm a code, save the recovery codes. */
export function MfaSetup({ onDone, onCancel }: { onDone: () => void; onCancel?: () => void }) {
  const start = useStartMfa()
  const confirm = useConfirmMfa()
  const [codes, setCodes] = useState<string[] | null>(null)

  if (codes) return <RecoveryCodesList codes={codes} onDone={onDone} />
  if (!start.data) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-muted">
          You will need an authenticator app on your phone, such as Microsoft Authenticator, Google Authenticator or 1Password.
        </p>
        <div className="flex gap-2">
          <Button variant="primary" size="sm" loading={start.isPending} onClick={() => start.mutate(undefined, { onError: (error) => toast.error(error.message) })}>
            Set up multi-factor authentication
          </Button>
          {onCancel && (
            <Button size="sm" onClick={onCancel}>
              Cancel
            </Button>
          )}
        </div>
      </div>
    )
  }
  return (
    <form
      className="space-y-4"
      onSubmit={(event) => {
        event.preventDefault()
        const code = String(new FormData(event.currentTarget).get("code") ?? "").trim()
        confirm.mutate(code, { onSuccess: (result) => setCodes(result.recovery_codes), onError: (error) => toast.error(error.message) })
      }}
    >
      <div className="flex flex-wrap items-start gap-5">
        <QrCode value={start.data.otpauth_uri} label="QR code for your authenticator app" />
        <div className="min-w-0 flex-1 space-y-3 text-sm">
          <p>1. Scan the code with your authenticator app.</p>
          <p className="text-muted">
            Cannot scan? Enter this key in the app instead:
            <code className="mt-1 block break-all rounded bg-surface-2 px-2 py-1 font-mono text-xs text-fg">{start.data.secret}</code>
          </p>
          <p>2. Enter the six-digit code the app shows.</p>
          <Field label="Code from the app">
            {(id) => <Input id={id} name="code" inputMode="numeric" autoComplete="one-time-code" required maxLength={6} className="max-w-40" />}
          </Field>
        </div>
      </div>
      <div className="flex gap-2">
        <Button type="submit" variant="primary" size="sm" loading={confirm.isPending}>
          Turn on
        </Button>
        {onCancel && (
          <Button size="sm" onClick={onCancel}>
            Cancel
          </Button>
        )}
      </div>
    </form>
  )
}
