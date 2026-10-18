/**
 * Data access for every page: TanStack Query hooks over the typed gateway client.
 *
 * Lists that change without the user doing anything (alerts, events, system status)
 * are polled; mutations invalidate what they change. Paginated lists ask for one row
 * more than a page to know whether there is a next page, since the gateway's list
 * endpoints do not return totals.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { PAGE_SIZE, POLL_INTERVAL_MS, type CaseStatus } from "@/lib/constants"

import type { paths } from "./schema"

import {
  api,
  unwrap,
  type Action,
  type Alert,
  type Asset,
  type Case,
  type AssetCreate,
  type DetectionRule,
  type DetectionRuleCreate,
  type Event,
  type EventCreate,
  type NotificationPreferences,
  type Playbook,
  type ResponseSettings,
  type Simulation,
  type SimulationCreate,
  type User,
} from "./client"

export type Page<T> = { rows: T[]; hasMore: boolean }

function toPage<T>(rows: T[]): Page<T> {
  return { rows: rows.slice(0, PAGE_SIZE), hasMore: rows.length > PAGE_SIZE }
}

function pageQuery(page: number) {
  return { limit: PAGE_SIZE + 1, skip: page * PAGE_SIZE }
}

/** Search endpoints take no filters, so filters are applied to the page of results. */
function matches<T extends Record<string, unknown>>(row: T, filters: Partial<Record<keyof T, unknown>>) {
  return Object.entries(filters).every(([key, value]) => !value || row[key] === value)
}

// ---------------------------------------------------------------------------- Auth

export function useUpdateProfile() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { firstName?: string | null; lastName?: string | null; email?: string | null }) =>
      unwrap(api.PUT("/api/v1/auth/me", { body })),
    onSuccess: (user: User) => queryClient.setQueryData(["me"], user),
  })
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      unwrap(api.POST("/api/v1/auth/me/change-password", { body })),
  })
}

export function useAuthConfig() {
  return useQuery({
    queryKey: ["auth", "config"],
    queryFn: () => unwrap(api.GET("/api/v1/auth/config")),
    staleTime: Infinity,
  })
}

// ---------------------------------------------------------------------------- Organisation

export function useCurrentTenant() {
  return useQuery({ queryKey: ["tenant"], queryFn: () => unwrap(api.GET("/api/v1/tenants/current")), staleTime: 5 * 60_000 })
}

export function useRenameTenant() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => unwrap(api.PATCH("/api/v1/tenants/current", { body: { name } })),
    onSuccess: (tenant) => queryClient.setQueryData(["tenant"], tenant),
  })
}

// ---------------------------------------------------------------------------- Users

/** Everyone with an account: for names, assignment and administration. */
export function useUsers() {
  return useQuery({
    queryKey: ["users"],
    queryFn: () => unwrap(api.GET("/api/v1/users/", { params: { query: { limit: 500 } } })),
    staleTime: 60_000,
  })
}

/** "Ann Analyst", or the username when no name is set. */
export function displayName(user: Pick<User, "username" | "firstName" | "lastName">): string {
  return [user.firstName, user.lastName].filter(Boolean).join(" ") || user.username
}

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { username: string; email: string; firstName?: string | null; lastName?: string | null; role: "admin" | "analyst" }) =>
      unwrap(api.POST("/api/v1/users/", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  })
}

export function useUpdateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, ...body }: { userId: string; role?: "admin" | "analyst"; active?: boolean }) =>
      unwrap(api.PATCH("/api/v1/users/{user_id}", { params: { path: { user_id: userId } }, body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  })
}

export function useResetPassword() {
  return useMutation({
    mutationFn: (userId: string) =>
      unwrap(api.POST("/api/v1/users/{user_id}/reset-password", { params: { path: { user_id: userId } } })),
  })
}

// ---------------------------------------------------------------------------- Cases

export function useCases({ status, page }: { status?: string; page: number }) {
  return useQuery({
    queryKey: ["cases", "list", { status, page }],
    queryFn: async (): Promise<Page<Case>> => {
      const query = status === "active" ? { open_only: true } : { status: status ? [status as CaseStatus] : undefined }
      return toPage(await unwrap(api.GET("/api/v1/cases/", { params: { query: { ...query, ...pageQuery(page) } } })))
    },
    placeholderData: keepPreviousData,
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useCase(caseId: string) {
  return useQuery({
    queryKey: ["cases", "detail", caseId],
    queryFn: () => unwrap(api.GET("/api/v1/cases/{case_id}", { params: { path: { case_id: caseId } } })),
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useCaseEvidence(caseId: string) {
  return useQuery({
    queryKey: ["cases", "evidence", caseId],
    queryFn: () => unwrap(api.GET("/api/v1/cases/{case_id}/evidence", { params: { path: { case_id: caseId } } })),
  })
}

export function useUpdateCase(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { status?: CaseStatus; priority?: Case["priority"]; owner_id?: string | null; title?: string }) =>
      unwrap(api.PATCH("/api/v1/cases/{case_id}", { params: { path: { case_id: caseId } }, body })),
    onSuccess: (updated) => {
      queryClient.setQueryData(["cases", "detail", caseId], updated)
      void queryClient.invalidateQueries({ queryKey: ["cases", "list"] })
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

export function useAddCaseNote(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (text: string) => unwrap(api.POST("/api/v1/cases/{case_id}/notes", { params: { path: { case_id: caseId } }, body: { text } })),
    onSuccess: (updated) => queryClient.setQueryData(["cases", "detail", caseId], updated),
  })
}

// ---------------------------------------------------------------------------- Response

type ActionStatus = Action["status"]

export function useActions({ status, caseId, page = 0 }: { status?: ActionStatus[]; caseId?: string; page?: number }) {
  return useQuery({
    queryKey: ["actions", "list", { status, caseId, page }],
    queryFn: async () =>
      toPage(await unwrap(api.GET("/api/v1/response/actions", { params: { query: { status, case_id: caseId, ...pageQuery(page) } } }))),
    placeholderData: keepPreviousData,
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useActionTypes() {
  return useQuery({ queryKey: ["actions", "types"], queryFn: () => unwrap(api.GET("/api/v1/response/actions/types")) })
}

/** Approve, reject or undo an action. */
export function useDecideAction() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ actionId, decision, reason }: { actionId: string; decision: "approve" | "reject" | "undo"; reason?: string }) => {
      const params = { params: { path: { action_id: actionId } } }
      if (decision === "approve") return unwrap(api.POST("/api/v1/response/actions/{action_id}/approve", params))
      if (decision === "undo") return unwrap(api.POST("/api/v1/response/actions/{action_id}/undo", params))
      return unwrap(api.POST("/api/v1/response/actions/{action_id}/reject", { ...params, body: { reason: reason || null } }))
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["actions"] })
      void queryClient.invalidateQueries({ queryKey: ["cases"] })
    },
  })
}

export function useResponseSettings() {
  return useQuery({ queryKey: ["response", "settings"], queryFn: () => unwrap(api.GET("/api/v1/response/settings")) })
}

export function useUpdateResponseSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<ResponseSettings>) => unwrap(api.PATCH("/api/v1/response/settings", { body })),
    onSuccess: (updated) => queryClient.setQueryData(["response", "settings"], updated),
  })
}

export function usePlaybooks() {
  return useQuery({ queryKey: ["playbooks"], queryFn: () => unwrap(api.GET("/api/v1/playbooks/")) })
}

export function useUpdatePlaybook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ playbookId, ...body }: { playbookId: string; enabled?: boolean; mode?: Playbook["mode"] }) =>
      unwrap(api.PATCH("/api/v1/playbooks/{playbook_id}", { params: { path: { playbook_id: playbookId } }, body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["playbooks"] }),
  })
}

export function useRunPlaybook(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (playbookId: string) =>
      unwrap(api.POST("/api/v1/playbooks/{playbook_id}/run", { params: { path: { playbook_id: playbookId } }, body: { case_id: caseId } })),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["actions"] })
      void queryClient.invalidateQueries({ queryKey: ["cases", "detail", caseId] })
    },
  })
}

// ---------------------------------------------------------------------------- Notifications

export function useNotificationPreferences() {
  return useQuery({ queryKey: ["notifications", "preferences"], queryFn: () => unwrap(api.GET("/api/v1/notifications/preferences")) })
}

export function useUpdateNotificationPreferences() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<Omit<NotificationPreferences, "email_configured" | "address">>) =>
      unwrap(api.PATCH("/api/v1/notifications/preferences", { body })),
    onSuccess: (updated) => queryClient.setQueryData(["notifications", "preferences"], updated),
  })
}

export function useSendTestEmail() {
  return useMutation({ mutationFn: () => unwrap(api.POST("/api/v1/notifications/test")) })
}

type DeliveryStatus = NonNullable<NonNullable<paths["/api/v1/notifications/"]["get"]["parameters"]["query"]>["status"]>

export function useNotificationLog({ status, page }: { status?: DeliveryStatus; page: number }) {
  return useQuery({
    queryKey: ["notifications", "log", { status, page }],
    queryFn: async () =>
      toPage(
        await unwrap(
          api.GET("/api/v1/notifications/", {
            params: { query: { status, ...pageQuery(page) } },
          }),
        ),
      ),
    placeholderData: keepPreviousData,
    refetchInterval: POLL_INTERVAL_MS,
  })
}

// ---------------------------------------------------------------------------- Reports

export function useReports() {
  return useQuery({ queryKey: ["reports", "list"], queryFn: () => unwrap(api.GET("/api/v1/reports/")) })
}

export function useReport(reportId: string) {
  return useQuery({
    queryKey: ["reports", "detail", reportId],
    queryFn: () => unwrap(api.GET("/api/v1/reports/{report_id}", { params: { path: { report_id: reportId } } })),
  })
}

/** Make (or make again) the report for a month, YYYY-MM; by default the last full month. */
export function useMakeReport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (period?: string) => unwrap(api.POST("/api/v1/reports/", { body: { period: period ?? null } })),
    onSuccess: (report) => {
      queryClient.setQueryData(["reports", "detail", report.id], report)
      void queryClient.invalidateQueries({ queryKey: ["reports", "list"] })
    },
  })
}

/** Download a report as a PDF: fetched with the session, then saved by the browser. */
export function useDownloadReport() {
  return useMutation({
    mutationFn: async ({ reportId, period }: { reportId: string; period: string }) => {
      const blob = await unwrap(
        api.GET("/api/v1/reports/{report_id}/pdf", { params: { path: { report_id: reportId } }, parseAs: "blob" }),
      )
      const url = URL.createObjectURL(blob as Blob)
      const link = document.createElement("a")
      link.href = url
      link.download = `utdrs-report-${period}.pdf`
      link.click()
      URL.revokeObjectURL(url)
    },
  })
}

// ---------------------------------------------------------------------------- API keys

export function useApiKeys() {
  return useQuery({ queryKey: ["api-keys"], queryFn: () => unwrap(api.GET("/api/v1/api-keys/")) })
}

export function useApiKeyScopes() {
  return useQuery({ queryKey: ["api-keys", "scopes"], queryFn: () => unwrap(api.GET("/api/v1/api-keys/scopes")), staleTime: Infinity })
}

export function useCreateApiKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; scopes: string[]; expires_in_days?: number | null }) =>
      unwrap(api.POST("/api/v1/api-keys/", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["api-keys"] }),
  })
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (keyId: string) => unwrap(api.DELETE("/api/v1/api-keys/{key_id}", { params: { path: { key_id: keyId } } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["api-keys"] }),
  })
}

// ---------------------------------------------------------------------------- Audit log

export function useAuditLog({ action, page }: { action?: string; page: number }) {
  return useQuery({
    queryKey: ["audit-log", { action, page }],
    queryFn: async () =>
      toPage(await unwrap(api.GET("/api/v1/audit-log/", { params: { query: { action: action || undefined, ...pageQuery(page) } } }))),
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useVerifyAuditLog() {
  return useMutation({ mutationFn: () => unwrap(api.GET("/api/v1/audit-log/verify")) })
}

// ---------------------------------------------------------------------------- System status

export function useDetectionStatus() {
  return useQuery({
    queryKey: ["system", "detection"],
    queryFn: () => unwrap(api.GET("/api/v1/detection/")),
    refetchInterval: POLL_INTERVAL_MS * 2,
  })
}

export function useDatabaseHealth() {
  return useQuery({
    queryKey: ["system", "database"],
    queryFn: () => unwrap(api.GET("/api/v1/health/db")) as Promise<{ status: string; database: string }>,
    refetchInterval: POLL_INTERVAL_MS * 2,
  })
}

// ---------------------------------------------------------------------------- Alerts

export type AlertFilters = { status?: string; severity?: string; search?: string; page: number }

export function useAlerts({ status, severity, search, page }: AlertFilters) {
  return useQuery({
    queryKey: ["alerts", "list", { status, severity, search, page }],
    queryFn: async (): Promise<Page<Alert>> => {
      if (search) {
        const rows = await unwrap(
          api.GET("/api/v1/alerts/search/", { params: { query: { query: search, ...pageQuery(page) } } }),
        )
        const page_ = toPage(rows)
        return { ...page_, rows: page_.rows.filter((row) => matches(row, { status, severity })) }
      }
      const rows = await unwrap(
        api.GET("/api/v1/alerts/", {
          params: { query: { status: status || undefined, severity: severity || undefined, ...pageQuery(page) } },
        }),
      )
      return toPage(rows)
    },
    placeholderData: keepPreviousData,
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useLatestAlerts(limit: number) {
  return useQuery({
    queryKey: ["alerts", "latest", limit],
    queryFn: () => unwrap(api.GET("/api/v1/alerts/", { params: { query: { limit } } })),
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useAlertSummary() {
  return useQuery({
    queryKey: ["alerts", "summary"],
    queryFn: () => unwrap(api.GET("/api/v1/alerts/summary")),
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useAlert(alertId: string) {
  return useQuery({
    queryKey: ["alerts", "detail", alertId],
    queryFn: () => unwrap(api.GET("/api/v1/alerts/{alert_id}", { params: { path: { alert_id: alertId } } })),
    refetchInterval: POLL_INTERVAL_MS,
  })
}

function useAlertMutation<TVariables>(mutationFn: (variables: TVariables) => Promise<unknown>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  })
}

export function useUpdateAlertStatus(alertId: string) {
  return useAlertMutation((variables: { status: string; notes?: string }) =>
    unwrap(
      api.PATCH("/api/v1/alerts/{alert_id}/status", {
        params: {
          path: { alert_id: alertId },
          query: { status: variables.status, notes: variables.notes || undefined },
        },
      }),
    ),
  )
}

export function useAssignAlert(alertId: string) {
  return useAlertMutation((assignedTo: string) =>
    unwrap(
      api.PATCH("/api/v1/alerts/{alert_id}/assign", {
        params: { path: { alert_id: alertId }, query: { assigned_to: assignedTo } },
      }),
    ),
  )
}

export function useAlertTag(alertId: string) {
  return useAlertMutation(({ tag, remove }: { tag: string; remove?: boolean }) => {
    const options = { params: { path: { alert_id: alertId, tag } } }
    return unwrap(
      remove
        ? api.DELETE("/api/v1/alerts/{alert_id}/tags/{tag}", options)
        : api.POST("/api/v1/alerts/{alert_id}/tags/{tag}", options),
    )
  })
}

// ---------------------------------------------------------------------------- Events

export type EventFilters = { eventType?: string; search?: string; page: number }

export function useEvents({ eventType, search, page }: EventFilters) {
  return useQuery({
    queryKey: ["events", "list", { eventType, search, page }],
    queryFn: async (): Promise<Page<Event>> => {
      if (search) {
        const rows = await unwrap(
          api.GET("/api/v1/events/search/", { params: { query: { query: search, ...pageQuery(page) } } }),
        )
        const page_ = toPage(rows)
        return { ...page_, rows: page_.rows.filter((row) => matches(row, { event_type: eventType })) }
      }
      const rows = await unwrap(
        api.GET("/api/v1/events/", {
          params: { query: { event_type: eventType || undefined, ...pageQuery(page) } },
        }),
      )
      return toPage(rows)
    },
    placeholderData: keepPreviousData,
    refetchInterval: POLL_INTERVAL_MS,
  })
}

/** Most recent events by event time, for the activity chart. */
export function useRecentEvents(limit: number) {
  return useQuery({
    queryKey: ["events", "recent", limit],
    queryFn: () => unwrap(api.GET("/api/v1/events/recent/", { params: { query: { limit } } })),
    refetchInterval: POLL_INTERVAL_MS,
  })
}

/** How long after creation an event is polled while waiting for the engine's verdict. */
const ANALYSIS_WAIT_MS = 60_000

export function analysisOf(event: Event): { status?: string; alert_id?: string; error?: string } | undefined {
  return (event.metadata as { analysis?: { status?: string; alert_id?: string; error?: string } }).analysis
}

export function isAwaitingAnalysis(event: Event, now = Date.now()): boolean {
  return !analysisOf(event) && now - new Date(event.created_at).getTime() < ANALYSIS_WAIT_MS
}

export function useEvent(eventId: string) {
  return useQuery({
    queryKey: ["events", "detail", eventId],
    queryFn: () => unwrap(api.GET("/api/v1/events/{event_id}", { params: { path: { event_id: eventId } } })),
    refetchInterval: (query) => (query.state.data && isAwaitingAnalysis(query.state.data) ? 1500 : false),
  })
}

/** Several events by id (an alert's linked events). */
export function useEventsById(eventIds: string[]) {
  return useQuery({
    queryKey: ["events", "byId", eventIds],
    queryFn: () =>
      Promise.all(
        eventIds.map((eventId) =>
          unwrap(api.GET("/api/v1/events/{event_id}", { params: { path: { event_id: eventId } } })),
        ),
      ),
    enabled: eventIds.length > 0,
  })
}

export function useCreateEvent() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: EventCreate) => unwrap(api.POST("/api/v1/events/", { body })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] })
      // The engine's verdict may raise an alert shortly after.
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

// ---------------------------------------------------------------------------- Assets

export type AssetFilters = { assetType?: string; criticality?: string; search?: string; page: number }

export function useAssets({ assetType, criticality, search, page }: AssetFilters) {
  return useQuery({
    queryKey: ["assets", "list", { assetType, criticality, search, page }],
    queryFn: async (): Promise<Page<Asset>> => {
      if (search) {
        const rows = await unwrap(
          api.GET("/api/v1/assets/search/", { params: { query: { query: search, ...pageQuery(page) } } }),
        )
        const page_ = toPage(rows)
        return { ...page_, rows: page_.rows.filter((row) => matches(row, { asset_type: assetType, criticality })) }
      }
      const rows = await unwrap(
        api.GET("/api/v1/assets/", {
          params: {
            query: { asset_type: assetType || undefined, criticality: criticality || undefined, ...pageQuery(page) },
          },
        }),
      )
      return toPage(rows)
    },
    placeholderData: keepPreviousData,
  })
}

export function useAsset(assetId: string) {
  return useQuery({
    queryKey: ["assets", "detail", assetId],
    queryFn: () => unwrap(api.GET("/api/v1/assets/{asset_id}", { params: { path: { asset_id: assetId } } })),
  })
}

export function useCreateAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: AssetCreate) => unwrap(api.POST("/api/v1/assets/", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["assets"] }),
  })
}

export function useAssetVulnerability(assetId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ vulnerability, remove }: { vulnerability: string; remove?: boolean }) => {
      const options = { params: { path: { asset_id: assetId }, query: { vulnerability } } }
      return unwrap(
        remove
          ? api.PATCH("/api/v1/assets/{asset_id}/vulnerabilities/remove", options)
          : api.PATCH("/api/v1/assets/{asset_id}/vulnerabilities/add", options),
      )
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["assets"] }),
  })
}

// ---------------------------------------------------------------------------- Detection rules

export type RuleFilters = { status?: string; severity?: string; search?: string; page: number }

export function useRules({ status, severity, search, page }: RuleFilters) {
  return useQuery({
    queryKey: ["rules", "list", { status, severity, search, page }],
    queryFn: async (): Promise<Page<DetectionRule>> => {
      if (search) {
        const rows = await unwrap(
          api.GET("/api/v1/detection/rules/search/", { params: { query: { query: search, ...pageQuery(page) } } }),
        )
        const page_ = toPage(rows)
        return { ...page_, rows: page_.rows.filter((row) => matches(row, { status, severity })) }
      }
      const rows = await unwrap(
        api.GET("/api/v1/detection/rules", {
          params: { query: { status: status || undefined, severity: severity || undefined, ...pageQuery(page) } },
        }),
      )
      return toPage(rows)
    },
    placeholderData: keepPreviousData,
  })
}

export function useRule(ruleId: string) {
  return useQuery({
    queryKey: ["rules", "detail", ruleId],
    queryFn: () =>
      unwrap(api.GET("/api/v1/detection/rules/{rule_id}", { params: { path: { rule_id: ruleId } } })),
  })
}

export function useCreateRule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: DetectionRuleCreate) => unwrap(api.POST("/api/v1/detection/rules", { body })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
      void queryClient.invalidateQueries({ queryKey: ["system", "detection"] })
    },
  })
}

export function useUpdateRuleStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ ruleId, status }: { ruleId: string; status: string }) =>
      unwrap(
        api.PATCH("/api/v1/detection/rules/{rule_id}/status", {
          params: { path: { rule_id: ruleId }, query: { status } },
        }),
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
      void queryClient.invalidateQueries({ queryKey: ["system", "detection"] })
    },
  })
}

// ---------------------------------------------------------------------------- Simulations

export type SimulationFilters = { status?: string; page: number }

export function useSimulations({ status, page }: SimulationFilters) {
  return useQuery({
    queryKey: ["simulations", "list", { status, page }],
    queryFn: async (): Promise<Page<Simulation>> =>
      toPage(
        await unwrap(
          api.GET("/api/v1/simulation/", { params: { query: { status: status || undefined, ...pageQuery(page) } } }),
        ),
      ),
    placeholderData: keepPreviousData,
    refetchInterval: POLL_INTERVAL_MS,
  })
}

export function useCreateSimulation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: SimulationCreate) => unwrap(api.POST("/api/v1/simulation/", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["simulations"] }),
  })
}

export function useRunSimulation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ simulationId, action }: { simulationId: string; action: "start" | "stop" }) =>
      unwrap(
        api.POST(action === "start" ? "/api/v1/simulation/start" : "/api/v1/simulation/stop", {
          params: { query: { simulation_id: simulationId } },
        }),
      ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["simulations"] }),
  })
}
