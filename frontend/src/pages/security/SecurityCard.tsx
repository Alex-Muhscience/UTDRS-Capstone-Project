import { useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { toast } from "sonner"

import { useDisableMfa, useMfaStatus, useNewRecoveryCodes } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Input } from "@/components/ui/Field"
import { formatDateTime } from "@/lib/format"

import { MfaSetup, RecoveryCodesList } from "./MfaSetup"

/** Multi-factor authentication for your own account. */
export function SecurityCard() {
  const queryClient = useQueryClient()
  const status = useMfaStatus()
  const newCodes = useNewRecoveryCodes()
  const disable = useDisableMfa()
  const [settingUp, setSettingUp] = useState(false)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [code, setCode] = useState("")

  const data = status.data
  if (!data) return null

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          Multi-factor authentication
          {data.enabled ? <Badge tone="success">On</Badge> : <Badge tone="warning">Off</Badge>}
        </span>
      }
      description={
        data.required_by_organisation
          ? "Your organisation requires it."
          : "A code from your phone as well as your password, so a stolen password is not enough."
      }
    >
      {codes ? (
        <RecoveryCodesList codes={codes} onDone={() => setCodes(null)} />
      ) : !data.enabled ? (
        !data.encryption_available ? (
          <p className="text-sm text-muted">Not available yet: the gateway needs ENCRYPTION_KEY set. Ask your administrator.</p>
        ) : settingUp ? (
          <MfaSetup
            onDone={() => {
              setSettingUp(false)
              toast.success("Multi-factor authentication is on")
              void queryClient.invalidateQueries({ queryKey: ["mfa"] })
              void queryClient.invalidateQueries({ queryKey: ["me"] })
            }}
            onCancel={() => setSettingUp(false)}
          />
        ) : (
          <Button variant="primary" size="sm" onClick={() => setSettingUp(true)}>
            Set up
          </Button>
        )
      ) : (
        <div className="space-y-3 text-sm">
          <p className="text-muted">
            On since {formatDateTime(data.enabled_at)}. {data.recovery_codes_left} recovery code{data.recovery_codes_left === 1 ? "" : "s"} left.
          </p>
          <Input aria-label="Current code" value={code} onChange={(event) => setCode(event.target.value)} placeholder="Current code" maxLength={20} className="max-w-48" />
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              disabled={!code.trim()}
              loading={newCodes.isPending}
              onClick={() =>
                newCodes.mutate(code.trim(), {
                  onSuccess: (result) => {
                    setCode("")
                    setCodes(result.recovery_codes)
                  },
                  onError: (error) => toast.error(error.message),
                })
              }
            >
              New recovery codes
            </Button>
            {!data.required_by_organisation && (
              <Button
                size="sm"
                disabled={!code.trim()}
                loading={disable.isPending}
                onClick={() =>
                  disable.mutate(code.trim(), {
                    onSuccess: () => {
                      setCode("")
                      toast.success("Multi-factor authentication is off")
                    },
                    onError: (error) => toast.error(error.message),
                  })
                }
              >
                Turn off
              </Button>
            )}
          </div>
        </div>
      )}
    </Card>
  )
}
