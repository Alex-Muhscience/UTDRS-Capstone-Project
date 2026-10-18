import { useNavigate } from "react-router"
import { toast } from "sonner"

import { useCheckEmail } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"

/** Check a suspicious email someone received: UTDRS reads it from their mailbox and the engine judges it. */
export function CheckEmailDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const check = useCheckEmail()
  const navigate = useNavigate()

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Check an email"
      description="UTDRS reads the message's headers, sender, links and attachments from the recipient's Microsoft 365 mailbox, and the engine judges it. The message's text is not kept."
      onSubmit={(event) => {
        const data = new FormData(event.currentTarget)
        check.mutate(
          { recipient: String(data.get("recipient") ?? "").trim(), internet_message_id: String(data.get("message_id") ?? "").trim() },
          {
            onSuccess: (result) => {
              onClose()
              if (result.alert_id) {
                toast.error("This email looks malicious")
                void navigate(`/alerts/${result.alert_id}`)
              } else {
                toast.success(result.already_checked ? "Checked before: here is what UTDRS found" : "Nothing malicious found")
                void navigate(`/events/${result.event_id}`)
              }
            },
            onError: (error) => toast.error(error.message),
          },
        )
      }}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={check.isPending}>
            Check
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Recipient" required>
          {(id) => <Input id={id} name="recipient" type="email" required placeholder="ana@contoso.com" autoComplete="off" />}
        </Field>
        <Field label="Message ID" required hint="The Message-ID header, from the message's details or headers in Outlook.">
          {(id, describedBy) => <Input id={id} name="message_id" required aria-describedby={describedBy} placeholder="<abc123@mail.example.com>" autoComplete="off" />}
        </Field>
      </div>
    </Dialog>
  )
}
