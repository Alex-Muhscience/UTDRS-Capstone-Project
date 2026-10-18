import { CheckCircle2, Circle, CircleAlert } from "lucide-react"
import type { ReactNode } from "react"
import { Link, useNavigate } from "react-router"
import { toast } from "sonner"

import { useCurrentTenant, useDismissOnboarding, useMakeReport, useOnboarding, useRenameTenant, useSendTestEmail, useUpdateResponseSettings } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Button, ButtonLink } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState, SkeletonRows } from "@/components/ui/States"

const MODES = [
  { mode: "approval", label: "Ask before acting", hint: "Recommended to start: you approve each action" },
  { mode: "automatic", label: "Act on its own", hint: "Within the safety limits, for the fastest response" },
  { mode: "notify", label: "Only suggest", hint: "UTDRS tells you what it would do" },
] as const

function NameStep() {
  const tenant = useCurrentTenant()
  const rename = useRenameTenant()
  if (!tenant.data) return null
  return (
    <form
      className="flex gap-2"
      onSubmit={(event) => {
        event.preventDefault()
        const name = String(new FormData(event.currentTarget).get("organisation") ?? "").trim()
        if (name) rename.mutate(name, { onSuccess: () => toast.success("Organisation named"), onError: (error) => toast.error(error.message) })
      }}
    >
      <Input aria-label="Organisation name" name="organisation" defaultValue={tenant.data.name} maxLength={100} className="max-w-xs" />
      <Button type="submit" size="sm" loading={rename.isPending}>
        Save
      </Button>
    </form>
  )
}

function ResponseStep() {
  const update = useUpdateResponseSettings()
  return (
    <div className="flex flex-wrap gap-2">
      {MODES.map(({ mode, label, hint }) => (
        <Button
          key={mode}
          size="sm"
          title={hint}
          disabled={update.isPending}
          onClick={() => update.mutate({ mode }, { onSuccess: () => toast.success(`${label}: saved`), onError: (error) => toast.error(error.message) })}
        >
          {label}
        </Button>
      ))}
    </div>
  )
}

function EmailStep() {
  const test = useSendTestEmail()
  return (
    <Button
      size="sm"
      loading={test.isPending}
      onClick={() =>
        test.mutate(undefined, {
          onSuccess: (result) => (result.sent ? toast.success("Test email sent: check your inbox") : toast.error(`Not sent: ${result.error ?? "unknown error"}`)),
          onError: (error) => toast.error(error.message),
        })
      }
    >
      Send me a test email
    </Button>
  )
}

function ResultsStep() {
  const report = useMakeReport()
  const navigate = useNavigate()
  const now = new Date()
  const period = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`
  return (
    <div className="flex flex-wrap gap-2">
      <ButtonLink to="/cases" size="sm">
        Open cases
      </ButtonLink>
      <ButtonLink to="/events" size="sm">
        What has come in
      </ButtonLink>
      <Button
        size="sm"
        loading={report.isPending}
        onClick={() => report.mutate(period, { onSuccess: (made) => void navigate(`/reports/${made.id}`), onError: (error) => toast.error(error.message) })}
      >
        Make this month's report
      </Button>
    </div>
  )
}

export function GetStartedPage() {
  const onboarding = useOnboarding()
  const dismiss = useDismissOnboarding()
  const isAdmin = useIsAdmin()
  const navigate = useNavigate()

  if (onboarding.isPending) return <SkeletonRows rows={6} columns={1} />
  if (onboarding.isError) return <ErrorState error={onboarding.error} onRetry={() => void onboarding.refetch()} />
  const data = onboarding.data
  const email = data.steps.find((step) => step.key === "email")

  const actions: Record<string, ReactNode> = {
    name: isAdmin ? <NameStep /> : null,
    microsoft_365: isAdmin ? <ButtonLink to="/connectors" size="sm" variant="primary">Connect Microsoft 365</ButtonLink> : null,
    response: isAdmin ? <ResponseStep /> : null,
    team: isAdmin ? <ButtonLink to="/users" size="sm">Add people</ButtonLink> : null,
    email: email?.detail.startsWith("Email is not set up") ? null : <EmailStep />,
    results: <ResultsStep />,
  }

  return (
    <>
      <PageHeader
        title="Get started"
        description={
          data.complete
            ? "UTDRS is set up. It watches, explains and acts; come back here any time."
            : `${data.done} of ${data.total} done. Connect Microsoft 365 and UTDRS starts finding threats within minutes.`
        }
        actions={
          isAdmin && (
            <Button
              onClick={() =>
                dismiss.mutate(true, {
                  onSuccess: () => {
                    toast.success("Put away: find it again under your profile")
                    void navigate("/")
                  },
                })
              }
            >
              {data.complete ? "Done" : "Finish later"}
            </Button>
          )
        }
      />
      <div className="h-2 overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-label="Setup progress" aria-valuemin={0} aria-valuemax={data.total} aria-valuenow={data.done}>
        <div className="h-full bg-accent transition-all" style={{ width: `${(100 * data.done) / data.total}%` }} />
      </div>
      <ol className="mt-4 space-y-3">
        {data.steps.map((step, index) => (
          <li key={step.key}>
            <Card>
              <div className="flex items-start gap-3">
                {step.attention ? (
                  <CircleAlert className="mt-0.5 size-5 shrink-0 text-warning" aria-label="Needs attention" />
                ) : step.done ? (
                  <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-success" aria-label="Done" />
                ) : (
                  <Circle className="mt-0.5 size-5 shrink-0 text-subtle" aria-label="To do" />
                )}
                <div className="min-w-0 flex-1 space-y-2">
                  <p className="font-medium">
                    {index + 1}. {step.title}
                    {step.optional && <span className="ml-2 text-xs font-normal text-subtle">optional</span>}
                  </p>
                  <p className="text-sm text-muted">{step.detail}</p>
                  {(!step.done || step.attention || step.key === "results") && actions[step.key]}
                </div>
              </div>
            </Card>
          </li>
        ))}
      </ol>
      {!isAdmin && <p className="mt-4 text-sm text-subtle">An administrator connects services and chooses how UTDRS responds.</p>}
      <p className="mt-4 text-sm text-subtle">
        Want to see it working before connecting anything? <Link to="/events" className="text-accent hover:underline">Send a test event</Link>.
      </p>
    </>
  )
}
