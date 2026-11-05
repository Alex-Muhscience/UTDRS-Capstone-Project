import { CircleCheck } from "lucide-react"
import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import type { SsoSettings } from "@/api/client"
import { useRemoveSso, useSaveSso, useSsoSettings, useVerifySsoDomain } from "@/api/queries"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input, Textarea } from "@/components/ui/Field"
import { formatDateTime } from "@/lib/format"

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
  const [chosen, setChosen] = useState<"oidc" | "saml" | null>(null)
  const settings = sso.data
  // What is saved (OpenID Connect unless said otherwise), and what the form is showing.
  const saved = settings?.provider ?? "oidc"
  const provider = chosen ?? saved

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const text = (name: string) => String(form.get(name) ?? "").trim()
    setError(null)
    const details =
      provider === "saml"
        ? {
            provider: "saml" as const,
            idp_entity_id: text("idp_entity_id"),
            idp_sso_url: text("idp_sso_url"),
            ...(text("idp_certificate") ? { idp_certificate: text("idp_certificate") } : {}),
          }
        : {
            provider: "oidc" as const,
            issuer: text("issuer"),
            client_id: text("client_id"),
            ...(text("client_secret") ? { client_secret: text("client_secret") } : {}),
          }
    save.mutate(
      {
        ...details,
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
          <div className="flex gap-2" role="radiogroup" aria-label="Protocol">
            {(["oidc", "saml"] as const).map((option) => (
              <Button key={option} size="sm" variant={provider === option ? "primary" : "secondary"} aria-pressed={provider === option} onClick={() => setChosen(option)}>
                {option === "oidc" ? "OpenID Connect" : "SAML 2.0"}
              </Button>
            ))}
          </div>
          {provider === "oidc" ? (
            <p className="text-xs text-muted">
              Register UTDRS at the provider as a web application with the redirect URI{" "}
              <code className="break-all text-fg">{REDIRECT_URI}</code>, then enter what it gives you.
            </p>
          ) : settings.acs_url ? (
            <p className="text-xs text-muted">
              Add UTDRS to the identity provider as a SAML application with the entity ID{" "}
              <code className="break-all text-fg">{settings.sp_entity_id}</code> and the reply (ACS) URL{" "}
              <code className="break-all text-fg">{settings.acs_url}</code>, sending the email address as the NameID. Sign assertions (SHA-256) and do not encrypt them.
            </p>
          ) : (
            <p className="text-sm text-warning">SAML needs GATEWAY_URL set on the gateway: its public address, which identity providers post to.</p>
          )}
          {settings.configured && <Domains settings={settings} />}
          {/* Keyed on the saved settings, so the fields show what was saved. */}
          <form key={settings.updated_at ?? "new"} onSubmit={onSubmit} className="space-y-3">
            {provider === "oidc" ? (
              <>
                <Field label="Issuer" required hint="Such as https://login.microsoftonline.com/<tenant id>/v2.0 or https://accounts.google.com.">
                  {(id, describedBy) => <Input id={id} name="issuer" required defaultValue={settings.issuer ?? ""} aria-describedby={describedBy} />}
                </Field>
                <Field label="Client ID" required>
                  {(id) => <Input id={id} name="client_id" required defaultValue={settings.client_id ?? ""} />}
                </Field>
                <Field
                  label="Client secret"
                  required={!(settings.configured && saved === "oidc")}
                  hint={settings.configured && saved === "oidc" ? "Leave empty to keep the current one." : undefined}
                >
                  {(id, describedBy) => (
                    <Input id={id} name="client_secret" type="password" autoComplete="off" required={!(settings.configured && saved === "oidc")} aria-describedby={describedBy} />
                  )}
                </Field>
              </>
            ) : (
              <>
                <Field label="Identity provider entity ID" required>
                  {(id) => <Input id={id} name="idp_entity_id" required defaultValue={settings.idp_entity_id ?? ""} />}
                </Field>
                <Field label="Single sign-on URL" required hint="Where UTDRS sends people to sign in (HTTPS).">
                  {(id, describedBy) => <Input id={id} name="idp_sso_url" type="url" required defaultValue={settings.idp_sso_url ?? ""} aria-describedby={describedBy} />}
                </Field>
                <Field
                  label="Signing certificate"
                  required={!(settings.configured && saved === "saml")}
                  hint={
                    settings.idp_certificate_expires
                      ? `Current one expires ${formatDateTime(settings.idp_certificate_expires)}; leave empty to keep it.`
                      : "The provider's X.509 signing certificate (PEM, or the base64 from its metadata)."
                  }
                >
                  {(id, describedBy) => (
                    <Textarea
                      id={id}
                      name="idp_certificate"
                      rows={3}
                      className="font-mono text-xs"
                      required={!(settings.configured && saved === "saml")}
                      aria-describedby={describedBy}
                    />
                  )}
                </Field>
              </>
            )}
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
