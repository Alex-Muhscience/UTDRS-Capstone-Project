import { vi } from "vitest"

type Body = Record<string, unknown> | unknown[] | Response | null
type Handler = Body | ((request: Request, url: URL) => Body | Promise<Body>)

export type Call = { method: string; path: string; url: URL; body: string | undefined }

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })
}

/**
 * Stub fetch with a fake API gateway: routes are keyed "METHOD /path" and return
 * a JSON body (or a Response). Unknown routes answer 404. Every call is recorded.
 */
export function mockGateway(routes: Record<string, Handler>) {
  const calls: Call[] = []
  vi.stubGlobal(
    "fetch",
    vi.fn(async (request: Request) => {
      const url = new URL(request.url)
      const key = `${request.method} ${url.pathname}`
      calls.push({
        method: request.method,
        path: url.pathname,
        url,
        body: request.method === "GET" ? undefined : await request.clone().text(),
      })
      const route = routes[key]
      if (route === undefined) return json({ detail: `No mock for ${key}` }, 404)
      const result = typeof route === "function" ? await route(request, url) : route
      return result instanceof Response ? result : json(result)
    }),
  )
  return { calls, routes }
}
