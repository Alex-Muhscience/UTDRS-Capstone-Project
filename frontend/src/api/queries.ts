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
import { livePoll } from "@/lib/live"
import { createPasskey } from "@/lib/webauthn"

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
  type SuppressionCreate,
  type Simulation,
  type SimulationCreate,
  type Schemas,
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
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      unwrap(api.POST("/api/v1/auth/me/change-password", { body })),
    // Changing the password signs out everywhere else.
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["sessions"] }),
  })
}

/** Where the signed-in person is signed in. */
export function useMySessions() {
  return useQuery({ queryKey: ["sessions"], queryFn: () => unwrap(api.GET("/api/v1/auth/sessions")) })
}

export function useEndSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (sessionId: string) => unwrap(api.DELETE("/api/v1/auth/sessions/{session_id}", { params: { path: { session_id: sessionId } } })),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["sessions"] }),
  })
}

export function useEndOtherSessions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/auth/sessions/end-others")),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["sessions"] }),
  })
}

// ---------------------------------------------------------------------------- Account emails

/** Ask for a link to choose a new password (the answer is the same whether or not the account exists). */
export function useForgotPassword() {
  return useMutation({ mutationFn: (login: string) => unwrap(api.POST("/api/v1/auth/forgot-password", { body: { login } })) })
}

/** Choose a new password with the token from the emailed link. */
export function useChooseNewPassword() {
  return useMutation({
    mutationFn: (body: { token: string; new_password: string }) => unwrap(api.POST("/api/v1/auth/reset-password", { body })),
  })
}

export function useVerifyEmail() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (token: string) => unwrap(api.POST("/api/v1/auth/verify-email", { body: { token } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["me"] }),
  })
}

/** Send the confirmation link again, for someone who cannot sign in until they confirm. */
export function useResendVerification() {
  return useMutation({ mutationFn: (login: string) => unwrap(api.POST("/api/v1/auth/resend-verification", { body: { login } })) })
}

/** Send the signed-in person the link to confirm their email address. */
export function useSendMyVerification() {
  return useMutation({ mutationFn: () => unwrap(api.POST("/api/v1/auth/me/send-verification")) })
}

// ---------------------------------------------------------------------------- Single sign-on

/** Where to send someone to sign in with their organisation's identity provider. */
export function useStartSso() {
  return useMutation({
    mutationFn: (email: string) =>
      unwrap(api.POST("/api/v1/auth/sso/start", { body: { email, redirect_uri: `${window.location.origin}/sso/callback` } })),
  })
}

export function useSsoSettings(enabled = true) {
  return useQuery({ queryKey: ["sso"], queryFn: () => unwrap(api.GET("/api/v1/tenants/current/sso")), enabled })
}

export function useSaveSso() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Schemas["SsoUpdate"]) => unwrap(api.PUT("/api/v1/tenants/current/sso", { body })),
    onSuccess: (settings) => queryClient.setQueryData(["sso"], settings),
  })
}

export function useVerifySsoDomain() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (domain: string) => unwrap(api.POST("/api/v1/tenants/current/sso/domains/{domain}/verify", { params: { path: { domain } } })),
    onSuccess: (settings) => queryClient.setQueryData(["sso"], settings),
  })
}

export function useRemoveSso() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.DELETE("/api/v1/tenants/current/sso")),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["sso"] }),
  })
}

// ---------------------------------------------------------------------------- Passkeys

export function usePasskeys() {
  return useQuery({ queryKey: ["passkeys"], queryFn: () => unwrap(api.GET("/api/v1/auth/passkeys")) })
}

/** Create a passkey on this device and keep it with the account. */
export function useAddPasskey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (name: string) => {
      const options = (await unwrap(api.POST("/api/v1/auth/passkeys/register/options"))) as Record<string, unknown>
      const credential = await createPasskey(options)
      return unwrap(api.POST("/api/v1/auth/passkeys", { body: { credential, name } }))
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["passkeys"] }),
  })
}

export function useRemovePasskey() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (passkeyId: string) => unwrap(api.DELETE("/api/v1/auth/passkeys/{passkey_id}", { params: { path: { passkey_id: passkeyId } } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["passkeys"] }),
  })
}

// ---------------------------------------------------------------------------- SCIM

export type ScimStatus = { enabled: boolean; created_at?: string | null; last_used_at?: string | null }

export function useScimStatus() {
  return useQuery({ queryKey: ["scim"], queryFn: async () => (await unwrap(api.GET("/api/v1/tenants/current/scim"))) as ScimStatus })
}

/** Make the organisation's SCIM token (replacing any), shown once. */
export function useNewScimToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => (await unwrap(api.POST("/api/v1/tenants/current/scim/token"))) as { token: string; created_at: string },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scim"] }),
  })
}

export function useRevokeScimToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.DELETE("/api/v1/tenants/current/scim/token")),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scim"] }),
  })
}

// ---------------------------------------------------------------------------- Platform console

export function useOrganisations() {
  return useQuery({ queryKey: ["platform", "organisations"], queryFn: () => unwrap(api.GET("/api/v1/platform/organisations")), retry: false })
}

export function useOrganisation(tenantId: string) {
  return useQuery({
    queryKey: ["platform", "organisations", tenantId],
    queryFn: () => unwrap(api.GET("/api/v1/platform/organisations/{tenant_id}", { params: { path: { tenant_id: tenantId } } })),
    retry: false,
  })
}

function usePlatformMutation<TVariables, TResult>(mutationFn: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn, onSettled: () => queryClient.invalidateQueries({ queryKey: ["platform"] }) })
}

export function useCreateOrganisation() {
  return usePlatformMutation((body: { name: string; admin_username: string; admin_email: string }) =>
    unwrap(api.POST("/api/v1/platform/organisations", { body })),
  )
}

export function useAddOrganisationAdmin(tenantId: string) {
  return usePlatformMutation((body: { username: string; email: string }) =>
    unwrap(api.POST("/api/v1/platform/organisations/{tenant_id}/administrators", { params: { path: { tenant_id: tenantId } }, body })),
  )
}

export function useSetOrganisationSuspended(tenantId: string) {
  return usePlatformMutation((suspended: boolean) =>
    unwrap(api.PATCH("/api/v1/platform/organisations/{tenant_id}", { params: { path: { tenant_id: tenantId } }, body: { suspended } })),
  )
}

export function useDeleteOrganisation(tenantId: string) {
  return usePlatformMutation((confirmName: string) =>
    unwrap(api.DELETE("/api/v1/platform/organisations/{tenant_id}", { params: { path: { tenant_id: tenantId } }, body: { confirm_name: confirmName } })),
  )
}

export function usePlatformAdmins() {
  return useQuery({ queryKey: ["platform", "admins"], queryFn: () => unwrap(api.GET("/api/v1/platform/admins")), retry: false })
}

export function useSetPlatformAdmin() {
  return usePlatformMutation((body: { username: string; platform_admin: boolean }) => unwrap(api.PUT("/api/v1/platform/admins", { body })))
}

export function usePlatformAuditLog() {
  return useQuery({ queryKey: ["platform", "audit"], queryFn: () => unwrap(api.GET("/api/v1/platform/audit-log", { params: { query: { limit: 50 } } })), retry: false })
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
    onSuccess: (tenant) => {
      queryClient.setQueryData(["tenant"], tenant)
      void queryClient.invalidateQueries({ queryKey: ["onboarding"] })
    },
  })
}

// ---------------------------------------------------------------------------- Multi-factor authentication

export function useMfaStatus() {
  return useQuery({ queryKey: ["mfa"], queryFn: () => unwrap(api.GET("/api/v1/auth/mfa")) })
}

function useMfaMutation<TVariables, TResult>(mutationFn: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn,
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["mfa"] })
      void queryClient.invalidateQueries({ queryKey: ["me"] })
    },
  })
}

export function useStartMfa() {
  return useMfaMutation(() => unwrap(api.POST("/api/v1/auth/mfa/setup")))
}

/**
 * Turning MFA on refreshes nothing by itself: the recovery codes it returns are shown
 * once, so the page must not move on (the profile's "on" view, or past the setup gate)
 * until they are saved. The caller refreshes when the person has saved them.
 */
export function useConfirmMfa() {
  return useMutation({ mutationFn: (code: string) => unwrap(api.POST("/api/v1/auth/mfa/confirm", { body: { code } })) })
}

export function useNewRecoveryCodes() {
  return useMfaMutation((code: string) => unwrap(api.POST("/api/v1/auth/mfa/recovery-codes", { body: { code } })))
}

export function useDisableMfa() {
  return useMfaMutation((code: string) => unwrap(api.POST("/api/v1/auth/mfa/disable", { body: { code } })))
}

export function useRequireMfa() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (requireMfa: boolean) => unwrap(api.PATCH("/api/v1/tenants/current/security", { body: { require_mfa: requireMfa } })),
    onSuccess: (tenant) => queryClient.setQueryData(["tenant"], tenant),
  })
}

export function useResetMfa() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (userId: string) => unwrap(api.POST("/api/v1/users/{user_id}/reset-mfa", { params: { path: { user_id: userId } } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  })
}

/** Erase someone's personal data (cannot be undone). */
export function useEraseUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, confirmUsername }: { userId: string; confirmUsername: string }) =>
      unwrap(api.POST("/api/v1/users/{user_id}/erase", { params: { path: { user_id: userId } }, body: { confirm_username: confirmUsername } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  })
}

export function useSignOutEverywhere() {
  return useMutation({
    mutationFn: (userId: string) => unwrap(api.POST("/api/v1/users/{user_id}/sign-out", { params: { path: { user_id: userId } } })),
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
    refetchInterval: livePoll,
  })
}

/** Attach a file to a case: sent as a form, so the browser sets the boundary. */
export function useAttachFile(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (file: File) => {
      const form = new FormData()
      form.append("file", file, file.name)
      return unwrap(
        api.POST("/api/v1/cases/{case_id}/attachments", {
          params: { path: { case_id: caseId } },
          // FormData as it is; the generated type describes the form's fields.
          body: form as unknown as { file: string },
          bodySerializer: (body) => body as unknown as FormData,
        }),
      )
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cases", "detail", caseId] }),
  })
}

export function useDownloadAttachment(caseId: string) {
  return useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      const blob = await unwrap(
        api.GET("/api/v1/cases/{case_id}/attachments/{attachment_id}", {
          params: { path: { case_id: caseId, attachment_id: id } },
          parseAs: "blob",
        }),
      )
      const url = URL.createObjectURL(blob as Blob)
      const link = document.createElement("a")
      link.href = url
      link.download = name
      link.click()
      URL.revokeObjectURL(url)
    },
  })
}

export function useRemoveAttachment(caseId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (attachmentId: string) =>
      unwrap(api.DELETE("/api/v1/cases/{case_id}/attachments/{attachment_id}", { params: { path: { case_id: caseId, attachment_id: attachmentId } } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cases", "detail", caseId] }),
  })
}

export function useCase(caseId: string) {
  return useQuery({
    queryKey: ["cases", "detail", caseId],
    queryFn: () => unwrap(api.GET("/api/v1/cases/{case_id}", { params: { path: { case_id: caseId } } })),
    refetchInterval: livePoll,
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
    refetchInterval: livePoll,
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
    onSuccess: (updated) => {
      queryClient.setQueryData(["response", "settings"], updated)
      void queryClient.invalidateQueries({ queryKey: ["onboarding"] })
    },
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
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/notifications/test")),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["onboarding"] }),
  })
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

/** Download the audit log (JSON Lines, checkable outside UTDRS, or CSV), with the kind of action shown. */
export function useExportAuditLog() {
  return useMutation({
    mutationFn: async ({ format, action }: { format: "jsonl" | "csv"; action?: string }) => {
      const blob = await unwrap(
        api.GET("/api/v1/audit-log/export", { params: { query: { format, action: action || undefined } }, parseAs: "blob" }),
      )
      const url = URL.createObjectURL(blob as Blob)
      const link = document.createElement("a")
      link.href = url
      link.download = `utdrs-audit-log${action ? `-${action}` : ""}.${format}`
      link.click()
      URL.revokeObjectURL(url)
    },
  })
}

// ---------------------------------------------------------------------------- Tuning

export function useGiveFeedback(alertId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { verdict: "true_positive" | "false_positive" | "benign"; note?: string | null }) =>
      unwrap(api.POST("/api/v1/alerts/{alert_id}/feedback", { params: { path: { alert_id: alertId } }, body })),
    onSuccess: (result) => {
      queryClient.setQueryData(["alerts", "detail", alertId], result.alert)
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
      void queryClient.invalidateQueries({ queryKey: ["tuning", "quality"] })
    },
  })
}

export function useSuppressions() {
  return useQuery({ queryKey: ["tuning", "suppressions"], queryFn: () => unwrap(api.GET("/api/v1/tuning/suppressions")) })
}

export function useCreateSuppression() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: SuppressionCreate) => unwrap(api.POST("/api/v1/tuning/suppressions", { body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["tuning", "suppressions"] }),
  })
}

export function useUpdateSuppression() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ suppressionId, ...body }: { suppressionId: string; enabled?: boolean }) =>
      unwrap(api.PATCH("/api/v1/tuning/suppressions/{suppression_id}", { params: { path: { suppression_id: suppressionId } }, body })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["tuning", "suppressions"] }),
  })
}

export function useDeleteSuppression() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (suppressionId: string) =>
      unwrap(api.DELETE("/api/v1/tuning/suppressions/{suppression_id}", { params: { path: { suppression_id: suppressionId } } })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["tuning", "suppressions"] }),
  })
}

export function useDetectorQuality(days = 30) {
  return useQuery({
    queryKey: ["tuning", "quality", days],
    queryFn: () => unwrap(api.GET("/api/v1/tuning/quality", { params: { query: { days } } })),
  })
}

// ---------------------------------------------------------------------------- Connectors

export function useMicrosoft365() {
  return useQuery({ queryKey: ["connectors", "m365"], queryFn: () => unwrap(api.GET("/api/v1/connectors/microsoft-365")), refetchInterval: POLL_INTERVAL_MS })
}

function useConnectorMutation<TVariables, TResult>(mutationFn: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn,
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["connectors"] })
      void queryClient.invalidateQueries({ queryKey: ["actions", "types"] })
      void queryClient.invalidateQueries({ queryKey: ["onboarding"] })
    },
  })
}

export function useConnectOwnApp() {
  return useConnectorMutation((body: { azure_tenant_id: string; client_id: string; client_secret: string }) =>
    unwrap(api.PUT("/api/v1/connectors/microsoft-365", { body })),
  )
}

/** Start "Connect with Microsoft": where to send the administrator. */
export function useConsentUrl() {
  return useMutation({
    mutationFn: (redirectUri: string) => unwrap(api.POST("/api/v1/connectors/microsoft-365/consent-url", { body: { redirect_uri: redirectUri } })),
  })
}

export function useFinishConsent() {
  return useConnectorMutation(
    (body: { state: string; tenant?: string | null; admin_consent?: string | null; error?: string | null; error_description?: string | null }) =>
      unwrap(api.POST("/api/v1/connectors/microsoft-365/consent", { body })),
  )
}

export function useCheckMicrosoft365() {
  return useConnectorMutation(() => unwrap(api.POST("/api/v1/connectors/microsoft-365/check")))
}

export function usePollMicrosoft365() {
  return useConnectorMutation(() => unwrap(api.POST("/api/v1/connectors/microsoft-365/poll")))
}

export function useDisconnectMicrosoft365() {
  return useConnectorMutation(() => unwrap(api.DELETE("/api/v1/connectors/microsoft-365")))
}

export function useGoogleWorkspace() {
  return useQuery({ queryKey: ["connectors", "google"], queryFn: () => unwrap(api.GET("/api/v1/connectors/google-workspace")), refetchInterval: POLL_INTERVAL_MS })
}

export function useConnectGoogleWorkspace() {
  return useConnectorMutation((body: { service_account_key: string; admin_email: string }) =>
    unwrap(api.PUT("/api/v1/connectors/google-workspace", { body })),
  )
}

export function usePollGoogleWorkspace() {
  return useConnectorMutation(() => unwrap(api.POST("/api/v1/connectors/google-workspace/poll")))
}

export function useDisconnectGoogleWorkspace() {
  return useConnectorMutation(() => unwrap(api.DELETE("/api/v1/connectors/google-workspace")))
}

// ---------------------------------------------------------------------------- Email

/** Check a delivered email for phishing, by its recipient and Internet message id. */
export function useCheckEmail() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { recipient: string; internet_message_id: string }) => unwrap(api.POST("/api/v1/email/check", { body })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] })
      void queryClient.invalidateQueries({ queryKey: ["alerts"] })
    },
  })
}

// ---------------------------------------------------------------------------- Onboarding

export function useOnboarding() {
  return useQuery({ queryKey: ["onboarding"], queryFn: () => unwrap(api.GET("/api/v1/onboarding/")), refetchInterval: POLL_INTERVAL_MS })
}

export function useDismissOnboarding() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (dismissed: boolean) => unwrap(api.PATCH("/api/v1/onboarding/", { body: { dismissed } })),
    onSuccess: (updated) => queryClient.setQueryData(["onboarding"], updated),
  })
}

// ---------------------------------------------------------------------------- Retention

export function useRetention() {
  return useQuery({ queryKey: ["retention"], queryFn: () => unwrap(api.GET("/api/v1/retention/")) })
}

export function useUpdateRetention() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<Record<"events" | "alerts" | "cases" | "actions" | "notifications" | "labels", number>>) =>
      unwrap(api.PATCH("/api/v1/retention/", { body })),
    onSuccess: (updated) => queryClient.setQueryData(["retention"], updated),
  })
}

export function useRunRetention() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/retention/run")),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["retention"] }),
  })
}

// ---------------------------------------------------------------------------- Webhooks

export function useWebhooks() {
  return useQuery({ queryKey: ["webhooks", "list"], queryFn: () => unwrap(api.GET("/api/v1/webhooks/")), refetchInterval: POLL_INTERVAL_MS })
}

export function useWebhookEvents() {
  return useQuery({ queryKey: ["webhooks", "events"], queryFn: () => unwrap(api.GET("/api/v1/webhooks/events")), staleTime: Infinity })
}

export function useDeliveries(webhookId: string | null) {
  return useQuery({
    queryKey: ["webhooks", "deliveries", webhookId],
    queryFn: () => unwrap(api.GET("/api/v1/webhooks/{webhook_id}/deliveries", { params: { path: { webhook_id: webhookId ?? "" } } })),
    enabled: webhookId !== null,
    refetchInterval: 5_000,
  })
}

function useWebhookMutation<TVariables, TResult>(mutationFn: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn, onSettled: () => queryClient.invalidateQueries({ queryKey: ["webhooks"] }) })
}

export function useCreateWebhook() {
  return useWebhookMutation((body: { name: string; url: string; events: string[] }) => unwrap(api.POST("/api/v1/webhooks/", { body })))
}

export function useUpdateWebhook() {
  return useWebhookMutation(({ webhookId, ...body }: { webhookId: string; enabled?: boolean }) =>
    unwrap(api.PATCH("/api/v1/webhooks/{webhook_id}", { params: { path: { webhook_id: webhookId } }, body })),
  )
}

export function useTestWebhook() {
  return useWebhookMutation((webhookId: string) => unwrap(api.POST("/api/v1/webhooks/{webhook_id}/test", { params: { path: { webhook_id: webhookId } } })))
}

export function useRotateWebhookSecret() {
  return useWebhookMutation((webhookId: string) =>
    unwrap(api.POST("/api/v1/webhooks/{webhook_id}/rotate-secret", { params: { path: { webhook_id: webhookId } } })),
  )
}

export function useDeleteWebhook() {
  return useWebhookMutation((webhookId: string) => unwrap(api.DELETE("/api/v1/webhooks/{webhook_id}", { params: { path: { webhook_id: webhookId } } })))
}

export function useRedeliver() {
  return useWebhookMutation((deliveryId: string) =>
    unwrap(api.POST("/api/v1/webhooks/deliveries/{delivery_id}/redeliver", { params: { path: { delivery_id: deliveryId } } })),
  )
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
    refetchInterval: livePoll,
  })
}

export function useLatestAlerts(limit: number) {
  return useQuery({
    queryKey: ["alerts", "latest", limit],
    queryFn: () => unwrap(api.GET("/api/v1/alerts/", { params: { query: { limit } } })),
    refetchInterval: livePoll,
  })
}

export function useAlertSummary() {
  return useQuery({
    queryKey: ["alerts", "summary"],
    queryFn: () => unwrap(api.GET("/api/v1/alerts/summary")),
    refetchInterval: livePoll,
  })
}

export function useAlert(alertId: string) {
  return useQuery({
    queryKey: ["alerts", "detail", alertId],
    queryFn: () => unwrap(api.GET("/api/v1/alerts/{alert_id}", { params: { path: { alert_id: alertId } } })),
    refetchInterval: livePoll,
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

export type Analysis = {
  /** queued and analysing: waiting for the engine; then threat, clean or error. */
  status?: string
  alert_id?: string
  error?: string
  attempts?: number
  next_attempt_at?: string
}

export function analysisOf(event: Event): Analysis | undefined {
  return (event.metadata as { analysis?: Analysis }).analysis
}

export function isAwaitingAnalysis(event: Event, now = Date.now()): boolean {
  const status = analysisOf(event)?.status
  if (status === "queued" || status === "analysing") return true
  return !status && now - new Date(event.created_at).getTime() < ANALYSIS_WAIT_MS
}

/** Queued after the engine could not be reached: the gateway tries again by itself. */
export function isRetryingAnalysis(event: Event): boolean {
  const analysis = analysisOf(event)
  return analysis?.status === "queued" && (analysis.attempts ?? 0) > 0
}

export function useReanalyseEvent() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (eventId: string) => unwrap(api.POST("/api/v1/events/{event_id}/reanalyse", { params: { path: { event_id: eventId } } })),
    onSuccess: (event) => {
      queryClient.setQueryData(["events", "detail", event.id], event)
      void queryClient.invalidateQueries({ queryKey: ["events"] })
    },
  })
}

/** Administrators: queue every event whose analysis failed to be analysed again. */
export function useReanalyseFailed() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/events/reanalyse", { body: {} })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] })
      void queryClient.invalidateQueries({ queryKey: ["system", "detection"] })
    },
  })
}

export function useEvent(eventId: string) {
  return useQuery({
    queryKey: ["events", "detail", eventId],
    queryFn: () => unwrap(api.GET("/api/v1/events/{event_id}", { params: { path: { event_id: eventId } } })),
    // Quickly while the engine is expected any moment; slowly while the gateway retries.
    refetchInterval: (query) => {
      const event = query.state.data
      if (!event || !isAwaitingAnalysis(event)) return false
      return isRetryingAnalysis(event) ? 10_000 : 1500
    },
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

export type RuleTestCase = Schemas["RuleTestCase"]

/** Run a saved rule's test cases. */
export function useRunRuleTests(ruleId: string) {
  return useMutation({
    mutationFn: () => unwrap(api.POST("/api/v1/detection/rules/{rule_id}/test", { params: { path: { rule_id: ruleId } } })),
  })
}

/** Replace a rule's test cases (refused when they would fail). */
export function useSaveRuleTestCases(ruleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (testCases: RuleTestCase[]) =>
      unwrap(api.PUT("/api/v1/detection/rules/{rule_id}", { params: { path: { rule_id: ruleId } }, body: { test_cases: testCases } })),
    onSuccess: (rule) => {
      queryClient.setQueryData(["rules", "detail", ruleId], rule)
      void queryClient.invalidateQueries({ queryKey: ["rules", "versions", ruleId] })
    },
  })
}

export function useRuleVersions(ruleId: string) {
  return useQuery({
    queryKey: ["rules", "versions", ruleId],
    queryFn: () => unwrap(api.GET("/api/v1/detection/rules/{rule_id}/versions", { params: { path: { rule_id: ruleId } } })),
  })
}

export function useRestoreRuleVersion(ruleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (version: number) =>
      unwrap(api.POST("/api/v1/detection/rules/{rule_id}/versions/{version}/restore", { params: { path: { rule_id: ruleId, version } } })),
    onSuccess: (rule) => {
      queryClient.setQueryData(["rules", "detail", ruleId], rule)
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
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
