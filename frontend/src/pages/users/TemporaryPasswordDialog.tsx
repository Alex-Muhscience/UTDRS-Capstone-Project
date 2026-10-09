import { Check, Copy } from "lucide-react"
import { useState } from "react"

import type { UserWithPassword } from "@/api/client"
import { displayName } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/ui/Dialog"

/** Shows a new account's or a reset account's temporary password, once. */
export function TemporaryPasswordDialog({ result, onClose }: { result: UserWithPassword | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  return (
    <Dialog
      open={result !== null}
      onClose={() => {
        setCopied(false)
        onClose()
      }}
      title="Temporary password"
      description={result && `Give this to ${displayName(result.user)} privately. It is shown only now; they should change it after signing in.`}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {result && (
        <div className="space-y-3">
          <p className="text-sm text-muted">
            Username <code className="font-mono text-fg">{result.user.username}</code>
          </p>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 p-3">
            <code className="flex-1 font-mono text-sm break-all" aria-label="Temporary password">
              {result.temporary_password}
            </code>
            <Button
              size="sm"
              onClick={() => {
                void navigator.clipboard?.writeText(result.temporary_password)
                setCopied(true)
              }}
            >
              {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  )
}
