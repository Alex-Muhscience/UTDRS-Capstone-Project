import { CircleCheck } from "lucide-react"
import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import type { SsoSettings } from "@/api/client"
import { useRemoveSso, useSaveSso, useSsoSettings, useVerifySsoDomain } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input } from "@/components/ui/Field"

const REDIRECT_URI = `${window.location.origin}/sso/callback`

function Toggle({ name, label, hint, defaultChecked }: { name: string; label: string; hint: string; defaultChecked: boolean }) {
  return (
    <label className="flex gap-2 text-sm">
      <input type="checkbox" name={name} defaultChecked={defaultChecked} className="mt-0.5 size-4 accent-accent" />
      <span>
        <span className="block font-medium">{label}</span>
        <span className="block text-xs text-muted">{hint}</span>
      </span>
    </label>
  )
}

function Domains({ settings }: { settings: SsoSettings }) {
  const verify = useVerifySsoDomain()
  return (
    <ul className="space-y-2" aria-label="Single sign-on domains">
      {settings.domains.map((domain) => (
        <li key={domain.domain} className="rounded-lg border border-border p-3 text-sm">
          <span className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium">{domain.domain}</span>
            {domain.verified ? (
              <Badge tone="success">
                <CircleCheck className="size-3" aria-hidden /> Verified
              </Badge>
            ) : (
              <Button
                size="sm"
                loading={verify.isPending && verify.variables === domain.domain}
                onClick={() =>
                  verify.mutate(domain.domain, {
                    onSuccess: () => toast.success(`${domain.domain} is verified`),
                    onError: (error) => toast.error(error.message),
                  })
                }
              >
                Verify {domain.domain}
              </Button>
            )}
          </span>
          {!domain.verified && (
            <span className="mt-2 block text-xs text-muted">
              Add a TXT record <code className="break-all text-fg">{domain.record_name}</code> with the value{" "}
              <code className="break-all text-fg">{domain.record_value}</code>, then verify. It shows the domain is yours.
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}

/** Single sign-on with the organisation's identity provider (administrators). */
export function SsoCard() {
  const sso = useSsoSettings()
  const save = useSaveSso()
  const remove = useRemoveSso()
  const [error, setError] = useState<string | null>(null)
  const settings = sso.data

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const text = (name: string) => String(form.get(name) ?? "").trim()
    setError(null)
    save.mutate(
      {
        issuer: text("issuer"),
        client_id: text("client_id"),
        ...(text("client_secret") ? { client_secret: text("client_secret") } : {}),
        domains: text("domains").split(/[\s,]+/).filter(Boolean),
        enabled: form.get("enabled") === "on",
        enforce: form.get("enforce") === "on",
        auto_provision: form.get("auto_provision") === "on",
      },
      { onSuccess: () => toast.success("Single sign-on saved"), onError: (caught) => setError(caught.message) },
    )
  }

  return (
    <Card
      title="Single sign-on"
      description="People sign in with your identity provider (Microsoft Entra ID, Google, Okta or any OpenID Connect provider)."
    >
      {!settings ? (
        <p className="text-sm text-muted">{sso.isError ? sso.error.message : "Loading…"}</p>
      ) : (
        <div className="space-y-4">
          <p className="text-xs text-muted">
            Register UTDRS at the provider as a web application with the redirect URI{" "}
            <code className="break-all text-fg">{REDIRECT_URI}</code>, then enter what it gives you.
          </p>
          {settings.configured && <Domains settings={settings} />}
          {/* Keyed on the saved settings, so the fields show what was saved. */}
          <form key={settings.updated_at ?? "new"} onSubmit={onSubmit} className="space-y-3">
            <Field label="Issuer" required hint="Such as https://login.microsoftonline.com/<tenant id>/v2.0 or https://accounts.google.com.">
              {(id, describedBy) => <Input id={id} name="issuer" required defaultValue={settings.issuer ?? ""} aria-describedby={describedBy} />}
            </Field>
            <Field label="Client ID" required>
              {(id) => <Input id={id} name="client_id" required defaultValue={settings.client_id ?? ""} />}
            </Field>
            <Field label="Client secret" required={!settings.configured} hint={settings.configured ? "Leave empty to keep the current one." : undefined}>
              {(id, describedBy) => (
                <Input id={id} name="client_secret" type="password" autoComplete="off" required={!settings.configured} aria-describedby={describedBy} />
              )}
            </Field>
            <Field label="Email domains" required hint="Separated by commas, such as contoso.com, contoso.co.uk.">
              {(id, describedBy) => (
                <Input id={id} name="domains" required defaultValue={settings.domains.map((d) => d.domain).join(", ")} aria-describedby={describedBy} />
              )}
            </Field>
            <Toggle name="enabled" label="On" hint="People from verified domains can sign in with it." defaultChecked={settings.enabled} />
            <Toggle
              name="auto_provision"
              label="Create accounts on first sign-in"
              hint="Someone from your domains without an account gets an analyst account."
              defaultChecked={settings.auto_provision}
            />
            <Toggle
              name="enforce"
              label="Require it"
              hint="Analysts can no longer sign in with a password. Administrators still can, with MFA, in case the provider fails."
              defaultChecked={settings.enforce}
            />
            {error && (
              <p className="text-sm text-danger" role="alert">
                {error}
              </p>
            )}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="primary" loading={save.isPending}>
                Save
              </Button>
              {settings.configured && (
                <Button
                  variant="danger"
                  loading={remove.isPending}
                  onClick={() =>
                    remove.mutate(undefined, {
                      onSuccess: () => toast.success("Single sign-on turned off"),
                      onError: (caught) => toast.error(caught.message),
                    })
                  }
                >
                  Turn off and forget
                </Button>
              )}
            </div>
          </form>
        </div>
      )}
    </Card>
  )
}
