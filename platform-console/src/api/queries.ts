import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { api, unwrap } from "./client"

// ---------------------------------------------------------------------------- You

export function useMe(enabled = true) {
  return useQuery({ queryKey: ["me"], queryFn: () => unwrap(api.GET("/api/v1/platform/auth/me")), enabled, retry: false })
}

export function useChangePassword() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) => unwrap(api.POST("/api/v1/platform/auth/password", { body })),
    onSuccess: () => queryClient.invalidateQueries(),
  })
}

// ---------------------------------------------------------------------------- Organisations

function useConsoleMutation<TVariables, TResult>(mutationFn: (variables: TVariables) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn, onSettled: () => queryClient.invalidateQueries({ queryKey: ["platform"] }) })
}

export function useOrganisations() {
  return useQuery({ queryKey: ["platform", "organisations"], queryFn: () => unwrap(api.GET("/api/v1/platform/organisations")), refetchInterval: 60_000 })
}

export function useOrganisation(tenantId: string) {
  return useQuery({
    queryKey: ["platform", "organisations", tenantId],
    queryFn: () => unwrap(api.GET("/api/v1/platform/organisations/{tenant_id}", { params: { path: { tenant_id: tenantId } } })),
  })
}

export function useCreateOrganisation() {
  return useConsoleMutation((body: { name: string; admin_username: string; admin_email: string }) => unwrap(api.POST("/api/v1/platform/organisations", { body })))
}

export function useAddOrganisationAdmin(tenantId: string) {
  return useConsoleMutation((body: { username: string; email: string }) =>
    unwrap(api.POST("/api/v1/platform/organisations/{tenant_id}/administrators", { params: { path: { tenant_id: tenantId } }, body })),
  )
}

export function useChangeOrganisation(tenantId: string) {
  return useConsoleMutation((body: { suspended?: boolean; msp?: boolean; managed_by?: string }) =>
    unwrap(api.PATCH("/api/v1/platform/organisations/{tenant_id}", { params: { path: { tenant_id: tenantId } }, body })),
  )
}

export function useDeleteOrganisation(tenantId: string) {
  return useConsoleMutation((confirmName: string) =>
    unwrap(api.DELETE("/api/v1/platform/organisations/{tenant_id}", { params: { path: { tenant_id: tenantId } }, body: { confirm_name: confirmName } })),
  )
}

// ---------------------------------------------------------------------------- Operators

export function useOperators() {
  return useQuery({ queryKey: ["platform", "operators"], queryFn: () => unwrap(api.GET("/api/v1/platform/operators")) })
}

export function useAddOperator() {
  return useConsoleMutation((body: { username: string; email: string }) => unwrap(api.POST("/api/v1/platform/operators", { body })))
}

export function useSetOperatorActive() {
  return useConsoleMutation(({ id, active }: { id: string; active: boolean }) =>
    unwrap(api.PATCH("/api/v1/platform/operators/{operator_id}", { params: { path: { operator_id: id } }, body: { active } })),
  )
}

export function useResetOperator() {
  return useConsoleMutation((id: string) => unwrap(api.POST("/api/v1/platform/operators/{operator_id}/reset", { params: { path: { operator_id: id } } })))
}

// ---------------------------------------------------------------------------- Audit log

export function useAuditLog() {
  return useQuery({
    queryKey: ["platform", "audit"],
    queryFn: () => unwrap(api.GET("/api/v1/platform/audit-log", { params: { query: { limit: 200 } } })),
    refetchInterval: 60_000,
  })
}
