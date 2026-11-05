import { MailWarning } from "lucide-react"
import { toast } from "sonner"

import { useAuthConfig, useSendMyVerification } from "@/api/queries"
import { useUser } from "@/auth/context"

/** Asks someone whose email address is not confirmed to confirm it (when this deployment can send email). */
export function ConfirmEmailBanner() {
  const user = useUser()
  const config = useAuthConfig()
  const send = useSendMyVerification()
  if (user.email_verified || !config.data?.password_reset) return null

  return (
    <div className="mb-6 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm" role="status">
      <MailWarning className="size-4 shrink-0 text-warning" aria-hidden />
      <span className="min-w-0 flex-1">
        Confirm your email address, <strong className="font-medium">{user.email}</strong>, with the link we sent you, so you can reset your
        password if you forget it.
      </span>
      {send.isSuccess ? (
        <span className="text-muted">{send.data.message}</span>
      ) : (
        <button
          type="button"
          className="font-medium text-accent hover:underline disabled:opacity-60"
          disabled={send.isPending}
          onClick={() => send.mutate(undefined, { onError: (error) => toast.error(error.message) })}
        >
          Send the link again
        </button>
      )}
    </div>
  )
}
