/**
 * Where the API gateway is, for the dashboard's hosted deployments.
 *
 * Chosen when the page loads, from the domain it is served on, rather than at build
 * time: the Vercel project's build settings are not under this repository's control.
 * Elsewhere (development, the Docker image) the API is on the same origin.
 */
export const DEPLOYMENTS: ReadonlyArray<{ host: RegExp; api: string }> = [
  // The dashboard on Vercel, and its preview deployments; the backend on Render (render.yaml).
  { host: /^utdrs-capstone-project(-[a-z0-9-]+)?\.vercel\.app$/, api: "https://utdrs-api-gateway.onrender.com" },
]

export function deployedApiUrl(hostname: string): string {
  return DEPLOYMENTS.find(({ host }) => host.test(hostname))?.api ?? ""
}
