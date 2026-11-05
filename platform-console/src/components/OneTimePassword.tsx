import { Check, Copy } from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/ui/Dialog"

/** A password shown once, with a copy button. */
export function OneTimePassword({ username, password, onClose }: { username: string; password: string | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <Dialog
      open={password !== null}
      onClose={onClose}
      title="Temporary password"
      description={`Shown only this once. Give it to ${username} by a safe channel; they choose their own password and set up a second factor when they first sign in.`}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className="space-y-3">
        <p className="text-sm">
          Username: <span className="font-mono">{username}</span>
        </p>
        <code className="block break-all rounded-lg bg-surface-2 p-3 font-mono text-sm">{password}</code>
        <Button
          size="sm"
          onClick={() => {
            void navigator.clipboard?.writeText(password ?? "")
            setCopied(true)
          }}
        >
          {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />} {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </Dialog>
  )
}
