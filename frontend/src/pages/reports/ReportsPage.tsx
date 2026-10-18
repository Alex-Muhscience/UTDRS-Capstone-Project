import { useState } from "react"
import { Link, useNavigate } from "react-router"
import { toast } from "sonner"

import { useMakeReport, useReports } from "@/api/queries"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input } from "@/components/ui/Field"
import { PageHeader } from "@/components/ui/PageHeader"
import { EmptyState, ErrorState, SkeletonRows } from "@/components/ui/States"
import { formatDateTime } from "@/lib/format"

function lastFullMonth(now = new Date()): string {
  const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1))
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`
}

export function ReportsPage() {
  const reports = useReports()
  const make = useMakeReport()
  const navigate = useNavigate()
  const [period, setPeriod] = useState(lastFullMonth())

  return (
    <>
      <PageHeader
        title="Reports"
        description="A month of security in plain words: what was found, what was done about it, what is still open and what to do next. Last month's is made on the 1st, and administrators are emailed."
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Monthly reports" bodyClassName="p-0" className="xl:col-span-2">
          {reports.isPending ? (
            <SkeletonRows rows={3} columns={2} />
          ) : reports.isError ? (
            <ErrorState error={reports.error} onRetry={() => void reports.refetch()} />
          ) : reports.data.length === 0 ? (
            <EmptyState title="No reports yet">Make one for any month that has started.</EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {reports.data.map((report) => (
                <li key={report.id} className="px-5 py-4">
                  <Link to={`/reports/${report.id}`} className="font-medium hover:text-accent">
                    {report.title}
                  </Link>
                  <p className="mt-1 text-sm text-muted">{report.headline.join(" ")}</p>
                  <p className="mt-1 text-xs text-subtle">Made {formatDateTime(report.generated_at)}</p>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Make a report" description="For any month that has started. Making one again updates it.">
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault()
              make.mutate(period, {
                onSuccess: (report) => void navigate(`/reports/${report.id}`),
                onError: (error) => toast.error(error.message),
              })
            }}
          >
            <Field label="Month">{(id) => <Input id={id} type="month" value={period} required onChange={(event) => setPeriod(event.target.value)} />}</Field>
            <Button type="submit" variant="primary" size="sm" loading={make.isPending}>
              Make report
            </Button>
          </form>
        </Card>
      </div>
    </>
  )
}
