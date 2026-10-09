import { toast } from "sonner"

import { useUpdateRuleStatus } from "@/api/queries"
import { Select } from "@/components/ui/Field"
import { RULE_STATUSES } from "@/lib/constants"

export function RuleStatusSelect({ ruleId, status, name }: { ruleId: string; status: string; name: string }) {
  const update = useUpdateRuleStatus()
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
