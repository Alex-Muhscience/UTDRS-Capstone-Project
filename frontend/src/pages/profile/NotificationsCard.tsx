import { toast } from "sonner"

import type { NotificationPreferences } from "@/api/client"
import { useNotificationPreferences, useSendTestEmail, useUpdateNotificationPreferences } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Select } from "@/components/ui/Field"

const NEW_CASES = [
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High and critical" },
  { value: "medium", label: "Medium and above" },
  { value: "low", label: "Low and above" },
  { value: "info", label: "Every case" },
  { value: "off", label: "None" },
]
const ACTIONS = [
  { value: "failed", label: "Only those that failed" },
  { value: "all", label: "All of them" },
  { value: "off", label: "None" },
]
const ON_OFF = [
  { value: "on", label: "Yes" },
  { value: "off", label: "No" },
]

type Changes = Partial<Omit<NotificationPreferences, "email_configured" | "address">>

/** What you are emailed about. Each change is saved as it is made. */
export function NotificationsCard() {
  const isAdmin = useIsAdmin()
  const preferences = useNotificationPreferences()
  const update = useUpdateNotificationPreferences()
  const test = useSendTestEmail()
  const save = (changes: Changes) => update.mutate(changes, { onSuccess: () => toast.success("Saved"), onError: (error) => toast.error(error.message) })

  const data = preferences.data
  if (!data) return null
  const off = !data.email

  return (
    <Card
      title="Email notifications"
      description={
        data.email_configured
          ? `Sent to ${data.address ?? "your email address"}.`
          : "Email is not set up on this UTDRS yet, so nothing is sent. Your administrator sets it up (SMTP_HOST)."
      }
    >
      <div className="space-y-4">
        <Field label="Email me">
          {(id) => <Select id={id} value={data.email ? "on" : "off"} options={ON_OFF} disabled={update.isPending} onChange={(event) => save({ email: event.target.value === "on" })} />}
        </Field>
        <Field label="New cases">
          {(id) => (
            <Select id={id} value={data.new_cases} options={NEW_CASES} disabled={off || update.isPending} onChange={(event) => save({ new_cases: event.target.value as Changes["new_cases"] })} />
          )}
        </Field>
        <Field label="Actions waiting for my decision">
          {(id) => <Select id={id} value={data.approvals ? "on" : "off"} options={ON_OFF} disabled={off || update.isPending} onChange={(event) => save({ approvals: event.target.value === "on" })} />}
        </Field>
        <Field label="Actions taken">
          {(id) => (
            <Select id={id} value={data.actions} options={ACTIONS} disabled={off || update.isPending} onChange={(event) => save({ actions: event.target.value as Changes["actions"] })} />
          )}
        </Field>
        {isAdmin && (
          <Field label="The monthly report">
            {(id) => <Select id={id} value={data.reports ? "on" : "off"} options={ON_OFF} disabled={off || update.isPending} onChange={(event) => save({ reports: event.target.value === "on" })} />}
          </Field>
        )}
        <Button
          size="sm"
          loading={test.isPending}
          disabled={!data.email_configured}
          onClick={() =>
            test.mutate(undefined, {
              onSuccess: (result) => (result.sent ? toast.success(`Test email sent to ${data.address ?? "you"}`) : toast.error(`Not sent: ${result.error ?? "unknown error"}`)),
              onError: (error) => toast.error(error.message),
            })
          }
        >
          Send me a test email
        </Button>
      </div>
    </Card>
  )
}
