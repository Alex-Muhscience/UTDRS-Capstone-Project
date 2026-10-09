import { toast } from "sonner"

import { useUpdateRuleStatus } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { StatusBadge } from "@/components/ui/Badge"
import { Select } from "@/components/ui/Field"
import { RULE_STATUSES } from "@/lib/constants"

/** Admins switch a rule's status here; everyone else sees the status. */
export function RuleStatusSelect({ ruleId, status, name }: { ruleId: string; status: string; name: string }) {
  const update = useUpdateRuleStatus()
  const isAdmin = useIsAdmin()
  if (!isAdmin) return <StatusBadge status={status} />
  return (
    <Select
      aria-label={`Status of ${name}`}
      value={status}
      disabled={update.isPending}
      onClick={(event) => event.stopPropagation()}
      onChange={(event) =>
        update.mutate(
          { ruleId, status: event.target.value },
          {
            onSuccess: () => toast.success(`${name} is now ${event.target.value}`),
            onError: (error) => toast.error(error.message),
          },
        )
      }
      options={RULE_STATUSES}
      className="h-8 w-32 text-xs"
    />
  )
}
