/**
 * Where the API gateway is, for the operator console's hosted deployments: chosen from the
 * domain the page is served on. Elsewhere (development, the Docker image) it is the same origin.
 */
export const DEPLOYMENTS: ReadonlyArray<{ host: RegExp; api: string }> = [
  // The operator console on Vercel (its own project), and its preview deployments.
  { host: /^utdrs-operator-console(-[a-z0-9-]+)?\.vercel\.app$/, api: "https://utdrs-api-gateway-1pjf.onrender.com" },
]

export function deployedApiUrl(hostname: string): string {
  return DEPLOYMENTS.find(({ host }) => host.test(hostname))?.api ?? ""
}
