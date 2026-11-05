/**
 * The browser's side of passkeys (WebAuthn): turning the gateway's JSON options into what
 * navigator.credentials expects, and the browser's answer back into JSON. Uses the
 * browser's own JSON helpers where it has them, and does it by hand otherwise.
 */

type Json = Record<string, unknown>

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && !!navigator.credentials
}

function fromBase64url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4)
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

function toBase64url(buffer: ArrayBuffer | null | undefined): string | null {
  if (!buffer) return null
  let binary = ""
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

type JsonCapable = typeof PublicKeyCredential & {
  parseCreationOptionsFromJSON?: (options: Json) => PublicKeyCredentialCreationOptions
  parseRequestOptionsFromJSON?: (options: Json) => PublicKeyCredentialRequestOptions
}

function creationOptions(options: Json): PublicKeyCredentialCreationOptions {
  const helper = (window.PublicKeyCredential as JsonCapable).parseCreationOptionsFromJSON
  if (helper) return helper(options)
  const user = options.user as Json
  return {
    ...(options as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromBase64url(options.challenge as string),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: fromBase64url(user.id as string) },
    excludeCredentials: ((options.excludeCredentials as Json[] | undefined) ?? []).map((c) => ({
      ...(c as unknown as PublicKeyCredentialDescriptor),
      id: fromBase64url(c.id as string),
    })),
  }
}

function requestOptions(options: Json): PublicKeyCredentialRequestOptions {
  const helper = (window.PublicKeyCredential as JsonCapable).parseRequestOptionsFromJSON
  if (helper) return helper(options)
  return {
    ...(options as unknown as PublicKeyCredentialRequestOptions),
    challenge: fromBase64url(options.challenge as string),
    allowCredentials: ((options.allowCredentials as Json[] | undefined) ?? []).map((c) => ({
      ...(c as unknown as PublicKeyCredentialDescriptor),
      id: fromBase64url(c.id as string),
    })),
  }
}

function toJson(credential: PublicKeyCredential): Json {
  const withJson = credential as unknown as { toJSON?: () => Json }
  if (typeof withJson.toJSON === "function") return withJson.toJSON()
  const attestation = credential.response as AuthenticatorAttestationResponse
  const assertion = credential.response as AuthenticatorAssertionResponse
  const created = "attestationObject" in credential.response
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: created
      ? {
          clientDataJSON: toBase64url(attestation.clientDataJSON),
          attestationObject: toBase64url(attestation.attestationObject),
          transports: attestation.getTransports?.() ?? [],
        }
      : {
          clientDataJSON: toBase64url(assertion.clientDataJSON),
          authenticatorData: toBase64url(assertion.authenticatorData),
          signature: toBase64url(assertion.signature),
          userHandle: toBase64url(assertion.userHandle),
        },
  }
}

/** Create a passkey with the gateway's options; its answer, as JSON. */
export async function createPasskey(options: Json): Promise<Json> {
  const credential = (await navigator.credentials.create({ publicKey: creationOptions(options) })) as PublicKeyCredential | null
  if (!credential) throw new Error("No passkey was created.")
  return toJson(credential)
}

/** Sign with a passkey the browser has for this site; its answer, as JSON. */
export async function signWithPasskey(options: Json): Promise<Json> {
  const credential = (await navigator.credentials.get({ publicKey: requestOptions(options) })) as PublicKeyCredential | null
  if (!credential) throw new Error("No passkey was chosen.")
  return toJson(credential)
}

/** A message for people when the browser refuses (cancelled, timed out, not allowed). */
export function passkeyErrorMessage(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "The passkey request was cancelled or timed out."
  }
  if (error instanceof DOMException && error.name === "InvalidStateError") return "This device already has a passkey for your account."
  return error instanceof Error ? error.message : "The passkey could not be used."
}
