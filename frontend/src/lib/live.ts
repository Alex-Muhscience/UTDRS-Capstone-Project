import { useQueryClient, type QueryClient } from "@tanstack/react-query"
import { useEffect, useSyncExternalStore } from "react"
import { useNavigate } from "react-router"
import { toast } from "sonner"

import { accessToken, gatewayUrl } from "@/api/client"

import { POLL_INTERVAL_MS } from "./constants"
import { ORGANISATION_HEADER, useActiveOrganisation } from "./organisation"

/**
 * Live updates: the gateway's stream (/api/v1/live, Server-Sent Events) says what changed in
 * the organisation, and the data it concerns is fetched again at once. While the stream is up,
 * the lists it covers are polled only now and then, as a safety net; while it is down, as before.
 *
 * fetch() rather than EventSource, so the access token goes in a header, not the URL.
 */

export type LiveMessage = { id: string | null; event: string; data: Record<string, unknown> }

/** How often the lists the stream covers are still polled while it is up. */
export const LIVE_POLL_MS = 120_000
const RETRY_MIN_MS = 1_000
const RETRY_MAX_MS = 30_000
const UNAVAILABLE_RETRY_MS = 300_000 // a gateway without the stream: ask again much later

let connected = false
const listeners = new Set<() => void>()

function setConnected(value: boolean): void {
  if (connected === value) return
  connected = value
  listeners.forEach((listener) => listener())
}

export function isLive(): boolean {
  return connected
}

/** Whether the dashboard is receiving live updates. */
export function useLive(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    isLive,
  )
}

/** refetchInterval for lists the stream covers: rarely while it is up, as usual otherwise. */
export function livePoll(): number {
  return connected ? LIVE_POLL_MS : POLL_INTERVAL_MS
}

/** Query keys (by their first part) each kind of change makes stale. */
const STALE: Record<string, string[][]> = {
  alert: [["alerts"], ["cases"], ["onboarding"]],
  case: [["cases"]],
  action: [["actions"], ["cases"]],
  report: [["reports"]],
  connector: [["connectors"]],
  inbox: [["inbox"]],
}
const EVERYTHING = [["alerts"], ["cases"], ["actions"], ["reports"], ["connectors"], ["onboarding"], ["inbox"]]

/** Parse Server-Sent Events from text, returning the complete messages and what is left over. */
export function parseEvents(buffer: string): { messages: LiveMessage[]; rest: string } {
  const blocks = buffer.replace(/\r\n/g, "\n").split("\n\n")
  const rest = blocks.pop() ?? ""
  const messages: LiveMessage[] = []
  for (const block of blocks) {
    let id: string | null = null
    let event = "message"
    const data: string[] = []
    for (const line of block.split("\n")) {
      if (!line || line.startsWith(":")) continue
      const colon = line.indexOf(":")
      const field = colon === -1 ? line : line.slice(0, colon)
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "")
      if (field === "id") id = value
      else if (field === "event") event = value
      else if (field === "data") data.push(value)
    }
    if (event === "message" && !data.length) continue // retry: and comments only
    let parsed: Record<string, unknown> = {}
    try {
      parsed = data.length ? (JSON.parse(data.join("\n")) as Record<string, unknown>) : {}
    } catch {
      // Not JSON: keep the event, without data.
    }
    messages.push({ id, event, data: parsed })
  }
  return { messages, rest }
}

const LOUD = new Set(["critical", "high"])

function handle(message: LiveMessage, queryClient: QueryClient, announce: (message: LiveMessage) => void): void {
  if (message.event === "ready") return
  const keys: string[][] = message.event === "resync" ? EVERYTHING : (STALE[message.event.split(".")[0] ?? ""] ?? [])
  keys.forEach((queryKey) => void queryClient.invalidateQueries({ queryKey }))
  announce(message)
}

/** Keep a live connection while signed in; mounted once, in the app's layout. */
export function useLiveUpdates(): void {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  // A service provider switching organisation reconnects, to hear of that one's changes.
  const organisation = useActiveOrganisation()

  useEffect(() => {
    const stop = new AbortController()
    const seen = new Set<string>()
    let lastId: string | null = null
    let retry = RETRY_MIN_MS
    let first = true

    const announce = (message: LiveMessage) => {
      if (message.event === "alert.created" && LOUD.has(String(message.data.severity))) {
        const id = String(message.data.id ?? "")
        toast.error(`New ${String(message.data.severity)} alert`, {
          description: String(message.data.title ?? ""),
          action: id ? { label: "Open", onClick: () => void navigate(`/alerts/${id}`) } : undefined,
        })
      } else if (message.event === "action.approval_requested") {
        toast("A response action is waiting for your decision", {
          action: { label: "Review", onClick: () => void navigate("/response") },
        })
      }
    }

    const wait = (ms: number) =>
      new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, ms)
        stop.signal.addEventListener("abort", () => {
          clearTimeout(timer)
          resolve()
        })
      })

    const connect = async (): Promise<number> => {
      const token = await accessToken()
      if (!token) return RETRY_MAX_MS
      const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: "text/event-stream" }
      if (lastId) headers["Last-Event-ID"] = lastId
      if (organisation) headers[ORGANISATION_HEADER] = organisation
      const response = await fetch(new Request(`${gatewayUrl()}/api/v1/live`, { headers, signal: stop.signal, cache: "no-store" }))
      if (response.status === 404) return UNAVAILABLE_RETRY_MS
      if (!response.ok || !response.body) return retry
      setConnected(true)
      retry = RETRY_MIN_MS
      // Back after a gap with nothing to resume from: whatever happened meanwhile is fetched.
      if (!first && !lastId) handle({ id: null, event: "resync", data: {} }, queryClient, () => {})
      first = false
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ""
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        const parsed = parseEvents(buffer + decoder.decode(value, { stream: true }))
        buffer = parsed.rest
        for (const message of parsed.messages) {
          if (message.id) {
            if (seen.has(message.id)) continue
            seen.add(message.id)
            lastId = message.id
          }
          handle(message, queryClient, announce)
        }
      }
      return RETRY_MIN_MS // the stream ended on its own (every few minutes): reconnect at once
    }

    void (async () => {
      while (!stop.signal.aborted) {
        let delay: number
        try {
          delay = await connect()
        } catch {
          delay = retry
          retry = Math.min(retry * 2, RETRY_MAX_MS)
        }
        setConnected(false)
        if (seen.size > 1000) seen.clear()
        await wait(delay)
      }
    })()

    return () => {
      stop.abort()
      setConnected(false)
    }
  }, [queryClient, navigate, organisation])
}
