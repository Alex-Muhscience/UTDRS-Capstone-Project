import { ShieldCheck } from "lucide-react"
import { useState, type FormEvent, type ReactNode } from "react"
import { Navigate, useNavigate } from "react-router"

import { api, errorMessage, startSession, type Schemas } from "@/api/client"
import { QrCode } from "@/components/QrCode"
import { Button } from "@/components/ui/Button"
import { Field, Input } from "@/components/ui/Field"
import { useSignedIn } from "@/lib/session"

type Step = Schemas["PasswordStep"]
type Signed = Schemas["Signed"]

function Frame({ title, description, children }: { title: string; description: ReactNode; children: ReactNode }) {
  return (
    <div className="grid min-h-dvh place-items-center bg-bg px-4 py-10 text-fg">
      <div className="w-full max-w-md space-y-6 rounded-2xl border border-border bg-surface p-6 shadow-card sm:p-8">
        <div className="space-y-2">
          <p className="flex items-center gap-2 text-xs font-semibold tracking-wide text-accent uppercase">
            <ShieldCheck className="size-4" aria-hidden /> UTDRS operator console
          </p>
          <h1 className="text-xl font-semibold">{title}</h1>
          <p className="text-sm text-muted">{description}</p>
        </div>
        {children}
      </div>
    </div>
  )
}

function Problem({ message }: { message: string | null }) {
  if (!message) return null
  return (
    <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm">
      {message}
    </p>
  )
}

/**
 * Operators sign in here, never with an organisation's account: a password, then always an
 * authenticator code. The first time, they set up the authenticator and get recovery codes.
 */
export function SignInPage() {
  const signedIn = useSignedIn()
  const navigate = useNavigate()
  const [step, setStep] = useState<Step | null>(null)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (signedIn && !codes) return <Navigate to="/" replace />

  async function submit<T>(event: FormEvent<HTMLFormElement>, call: (data: FormData) => Promise<{ data?: T; error?: unknown; response: Response }>, then: (data: T) => void) {
    event.preventDefault()
    setBusy(true)
    setProblem(null)
    try {
      const { data, error, response } = await call(new FormData(event.currentTarget))
      if (!response.ok || !data) setProblem(errorMessage(error, response.status))
      else then(data)
    } catch {
      setProblem(errorMessage(undefined, 0))
    } finally {
      setBusy(false)
    }
  }

  const signed = (result: Signed) => {
    startSession(result.access_token, result.expires_in)
    if (result.recovery_codes?.length) setCodes(result.recovery_codes)
    else void navigate("/", { replace: true })
  }

  if (codes) {
    return (
      <Frame title="Keep your recovery codes" description="Each works once, instead of an authenticator code, if you lose your phone. They are shown only now.">
        <ul className="grid grid-cols-2 gap-2 rounded-lg bg-surface-2 p-4 font-mono text-sm" aria-label="Recovery codes">
          {codes.map((code) => (
            <li key={code}>{code}</li>
          ))}
        </ul>
        <Button variant="primary" className="w-full" onClick={() => void navigate("/", { replace: true })}>
          I have kept them
        </Button>
      </Frame>
    )
  }

  if (step?.step === "enrol") {
    return (
      <Frame title="Set up your authenticator" description="The operator console always asks for a code from an authenticator app. Scan this with one, then enter the code it shows.">
        <div className="flex flex-col items-center gap-3">
          <QrCode value={step.otpauth_uri ?? ""} label="QR code for your authenticator app" />
          <p className="text-center text-xs text-muted">
            Or enter this key: <code className="font-mono break-all text-fg">{step.secret}</code>
          </p>
        </div>
        <form
          className="space-y-4"
          onSubmit={(event) =>
            void submit(event, (data) => api.POST("/api/v1/platform/auth/enrol", { body: { step_token: step.step_token, code: String(data.get("code") ?? "").trim() } }), signed)
          }
        >
          <Field label="Code from your authenticator" required>
            {(id) => <Input id={id} name="code" inputMode="numeric" autoComplete="one-time-code" required minLength={6} maxLength={6} autoFocus />}
          </Field>
          <Problem message={problem} />
          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            Confirm and sign in
          </Button>
        </form>
      </Frame>
    )
  }

  if (step?.step === "mfa") {
    return (
      <Frame title="Enter your code" description="From your authenticator app, or one of your recovery codes.">
        <form
          className="space-y-4"
          onSubmit={(event) =>
            void submit(event, (data) => api.POST("/api/v1/platform/auth/mfa", { body: { step_token: step.step_token, code: String(data.get("code") ?? "").trim() } }), signed)
          }
        >
          <Field label="Code" required>
            {(id) => <Input id={id} name="code" autoComplete="one-time-code" required minLength={6} maxLength={20} autoFocus />}
          </Field>
          <Problem message={problem} />
          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            Sign in
          </Button>
          <button type="button" className="w-full text-center text-xs text-muted hover:text-fg" onClick={() => setStep(null)}>
            Start again
          </button>
        </form>
      </Frame>
    )
  }

  return (
    <Frame title="Sign in" description="For the people who run this UTDRS deployment. Organisations' administrators and analysts sign in to the dashboard instead.">
      <form
        className="space-y-4"
        onSubmit={(event) =>
          void submit(
            event,
            (data) => api.POST("/api/v1/platform/auth/login", { body: { username: String(data.get("username") ?? "").trim(), password: String(data.get("password") ?? "") } }),
            setStep,
          )
        }
      >
        <Field label="Username" required>
          {(id) => <Input id={id} name="username" autoComplete="username" required autoFocus />}
        </Field>
        <Field label="Password" required>
          {(id) => <Input id={id} name="password" type="password" autoComplete="current-password" required />}
        </Field>
        <Problem message={problem} />
        <Button type="submit" variant="primary" className="w-full" loading={busy}>
          Continue
        </Button>
      </form>
    </Frame>
  )
}
