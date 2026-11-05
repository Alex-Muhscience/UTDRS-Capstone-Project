import { toast } from "sonner"

import { useChangePassword } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input } from "@/components/ui/Field"

/** A temporary password must be replaced before anything else. */
export function ChangePasswordPage({ forced }: { forced?: boolean }) {
  const change = useChangePassword()
  return (
    <div className="grid min-h-dvh place-items-center bg-bg px-4 text-fg">
      <Card className="w-full max-w-md" title="Choose your password" description={forced ? "You signed in with a temporary password. Choose your own to continue." : undefined}>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            const data = new FormData(event.currentTarget)
            const next = String(data.get("new") ?? "")
            if (next !== String(data.get("again") ?? "")) {
              toast.error("The new passwords are not the same")
              return
            }
            change.mutate(
              { current_password: String(data.get("current") ?? ""), new_password: next },
              { onSuccess: () => toast.success("Password changed"), onError: (error) => toast.error(error.message) },
            )
          }}
        >
          <Field label="Current (temporary) password" required>
            {(id) => <Input id={id} name="current" type="password" autoComplete="current-password" required />}
          </Field>
          <Field label="New password" hint="At least 12 characters" required>
            {(id) => <Input id={id} name="new" type="password" autoComplete="new-password" required minLength={12} />}
          </Field>
          <Field label="New password again" required>
            {(id) => <Input id={id} name="again" type="password" autoComplete="new-password" required minLength={12} />}
          </Field>
          <Button type="submit" variant="primary" className="w-full" loading={change.isPending}>
            Save and continue
          </Button>
        </form>
      </Card>
    </div>
  )
}
