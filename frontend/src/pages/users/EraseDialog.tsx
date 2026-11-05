import { useState } from "react"
import { toast } from "sonner"

import type { User } from "@/api/client"
import { displayName, useEraseUser } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/ui/Dialog"
import { Field, Input } from "@/components/ui/Field"

/** Erasing someone's personal data, after typing their username: it cannot be undone. */
export function EraseDialog({ user, onClose }: { user: User | null; onClose: () => void }) {
  const erase = useEraseUser()
  const [typed, setTyped] = useState("")

  function close() {
    setTyped("")
    erase.reset()
    onClose()
  }

  return (
    <Dialog
      open={user !== null}
      onClose={close}
      title={user ? `Erase ${displayName(user)}?` : "Erase"}
      description="Their name, username and email are replaced, their account is deactivated and its sign-in methods removed, their sessions end, and their name is replaced wherever it appears. The audit log is kept as it is. This cannot be undone."
      onSubmit={() =>
        user &&
        erase.mutate(
          { userId: user.id, confirmUsername: typed },
          {
            onSuccess: () => {
              toast.success("Erased")
              close()
            },
          },
        )
      }
      footer={
        <>
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="danger" loading={erase.isPending} disabled={!user || typed !== user.username}>
            Erase for good
          </Button>
        </>
      }
    >
      {user && (
        <Field label={`Type ${user.username} to confirm`} error={erase.isError ? erase.error.message : null}>
          {(id, describedBy) => <Input id={id} value={typed} onChange={(event) => setTyped(event.target.value)} autoComplete="off" aria-describedby={describedBy} />}
        </Field>
      )}
    </Dialog>
  )
}
