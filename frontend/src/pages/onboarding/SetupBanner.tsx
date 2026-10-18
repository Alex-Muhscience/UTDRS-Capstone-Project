import { Link } from "react-router"

import { useOnboarding } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"

/** On the overview, for administrators: how far setup has got, until it is finished or put away. */
export function SetupBanner() {
  const isAdmin = useIsAdmin()
  const onboarding = useOnboarding()
  const data = onboarding.data
  if (!isAdmin || !data || data.complete || data.dismissed) return null
  const next = data.steps.find((step) => !step.done && !step.optional)
  return (
    <Link
      to="/get-started"
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-accent/30 bg-accent/8 px-5 py-4 hover:bg-accent/12"
    >
      <span>
        <span className="block font-medium">Finish setting up UTDRS</span>
        <span className="block text-sm text-muted">
          {data.done} of {data.total} done{next ? `. Next: ${next.title.toLowerCase()}` : ""}
        </span>
      </span>
      <span className="text-sm font-medium text-accent">Continue →</span>
    </Link>
  )
}
