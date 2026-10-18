import { useEffect, useRef } from "react"
import { useNavigate, useSearchParams } from "react-router"
import { toast } from "sonner"

import { useFinishConsent } from "@/api/queries"
import { Card } from "@/components/ui/Card"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState } from "@/components/ui/States"

/** Where Microsoft sends an administrator back after "Connect with Microsoft". */
export function ConsentedPage() {
  const [params] = useSearchParams()
  const finish = useFinishConsent()
  const navigate = useNavigate()
  const sent = useRef(false)

  useEffect(() => {
    if (sent.current) return
    sent.current = true
    finish.mutate(
      {
        state: params.get("state") ?? "",
        tenant: params.get("tenant"),
        admin_consent: params.get("admin_consent"),
        error: params.get("error"),
        error_description: params.get("error_description"),
      },
      {
        onSuccess: () => {
          toast.success("Microsoft 365 connected")
          void navigate("/connectors", { replace: true })
        },
      },
    )
  }, [finish, navigate, params])

  return (
    <>
      <PageHeader title="Connecting Microsoft 365" />
      <Card>
        {finish.isError ? (
          <ErrorState error={finish.error} onRetry={() => void navigate("/connectors")} />
        ) : (
          <p className="text-sm text-muted">Finishing the connection…</p>
        )}
      </Card>
    </>
  )
}
