import { CircleCheck, CircleX, History, Play, Plus, Trash2 } from "lucide-react"
import { useState, type FormEvent } from "react"
import { toast } from "sonner"

import type { DetectionRule } from "@/api/client"
import { useRestoreRuleVersion, useRuleVersions, useRunRuleTests, useSaveRuleTestCases, useUsers, displayName, type RuleTestCase } from "@/api/queries"
import { useIsAdmin } from "@/auth/context"
import { Badge } from "@/components/ui/Badge"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Field, Input, Select, Textarea } from "@/components/ui/Field"
import { formatDateTime, formatRelative } from "@/lib/format"

const EXAMPLE = '{"event_type": "process", "process_name": "powershell.exe", "command_line": "powershell -enc ..."}'

/** Example events the rule must match, or must not: run on demand, and checked whenever the rule is saved. */
export function RuleTests({ rule }: { rule: DetectionRule }) {
  const isAdmin = useIsAdmin()
  const run = useRunRuleTests(rule.id)
  const save = useSaveRuleTestCases(rule.id)
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const cases = rule.test_cases ?? []
  const results = run.data?.results

  function saveCases(next: RuleTestCase[], done?: () => void) {
    setError(null)
    save.mutate(next, {
      onSuccess: () => {
        run.reset()
        done?.()
      },
      onError: (caught) => setError(caught.message),
    })
  }

  function add(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    let parsed: Record<string, unknown>
    try {
      parsed = JSON.parse(String(form.get("event") ?? ""))
    } catch {
      setError("The event is not valid JSON.")
      return
    }
    const added: RuleTestCase = {
      name: String(form.get("name") ?? "").trim(),
      event: parsed,
      expect: form.get("expect") === "no_match" ? "no_match" : "match",
    }
    saveCases([...cases, added], () => setAdding(false))
  }

  return (
    <Card
      title="Test cases"
      description="Example events this rule must match, or must not. They are checked whenever the rule is saved: a change that breaks one is not saved."
      actions={
        cases.length > 0 && (
          <Button size="sm" loading={run.isPending} onClick={() => run.mutate(undefined, { onError: (caught) => toast.error(caught.message) })}>
            <Play className="size-3.5" aria-hidden /> Run tests
          </Button>
        )
      }
    >
      {run.data && !run.data.ran && <p className="mb-3 text-sm text-muted">Not run: {run.data.reason}</p>}
      {run.data?.ran && (
        <p className={`mb-3 text-sm font-medium ${run.data.passed ? "text-success" : "text-danger"}`} role="status">
          {run.data.passed ? `All ${run.data.results.length} pass` : `${run.data.results.filter((r) => !r.passed).length} fail`}
        </p>
      )}
      {cases.length === 0 ? (
        <p className="text-sm text-muted">No test cases yet.</p>
      ) : (
        <ul className="divide-y divide-border" aria-label="Test cases">
          {cases.map((testCase, index) => {
            const result = results?.[index]
            return (
              <li key={`${testCase.name}-${index}`} className="flex items-start gap-2 py-2 text-sm">
                {result ? (
                  result.passed ? (
                    <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" aria-label="Passes" />
                  ) : (
                    <CircleX className="mt-0.5 size-4 shrink-0 text-danger" aria-label="Fails" />
                  )
                ) : null}
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2 font-medium">
                    {testCase.name}
                    <Badge>{testCase.expect === "no_match" ? "Must not match" : "Must match"}</Badge>
                  </span>
                  <code className="block truncate text-xs text-muted">{JSON.stringify(testCase.event)}</code>
                </span>
                {isAdmin && (
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Remove ${testCase.name}`}
                    disabled={save.isPending}
                    onClick={() => saveCases(cases.filter((_, i) => i !== index))}
                  >
                    <Trash2 className="size-3.5" aria-hidden />
                  </Button>
                )}
              </li>
            )
          })}
        </ul>
      )}
      {error && (
        <p className="mt-3 text-sm text-danger" role="alert">
          {error}
        </p>
      )}
      {isAdmin &&
        (adding ? (
          <form onSubmit={add} className="mt-4 space-y-3 border-t border-border pt-4">
            <Field label="Name" required>
              {(id) => <Input id={id} name="name" required maxLength={200} />}
            </Field>
            <Field label="Expect">
              {(id) => (
                <Select
                  id={id}
                  name="expect"
                  defaultValue="match"
                  options={[
                    { value: "match", label: "Must match" },
                    { value: "no_match", label: "Must not match" },
                  ]}
                />
              )}
            </Field>
            <Field label="Event (JSON)" required hint="As sent to the API: event_type, source, and the event's fields.">
              {(id, describedBy) => <Textarea id={id} name="event" required rows={4} placeholder={EXAMPLE} className="font-mono text-xs" aria-describedby={describedBy} />}
            </Field>
            <div className="flex gap-2">
              <Button type="submit" variant="primary" loading={save.isPending}>
                Add
              </Button>
              <Button onClick={() => setAdding(false)}>Cancel</Button>
            </div>
          </form>
        ) : (
          <Button size="sm" className="mt-3" onClick={() => setAdding(true)}>
            <Plus className="size-3.5" aria-hidden /> Add a test case
          </Button>
        ))}
    </Card>
  )
}

/** Every version of the rule; administrators can go back to one. */
export function RuleHistory({ rule }: { rule: DetectionRule }) {
  const isAdmin = useIsAdmin()
  const versions = useRuleVersions(rule.id)
  const users = useUsers()
  const restore = useRestoreRuleVersion(rule.id)
  const who = (id: string | null | undefined) => {
    const person = users.data?.find((user) => user.id === id)
    return person ? displayName(person) : id ? "a former user" : "UTDRS"
  }

  return (
    <Card title="History" description="Every change to this rule. Restoring an earlier version makes a new one.">
      {!versions.data ? (
        <p className="text-sm text-muted">{versions.isError ? versions.error.message : "Loading…"}</p>
      ) : versions.data.length === 0 ? (
        <p className="text-sm text-muted">No changes recorded yet.</p>
      ) : (
        <ol className="space-y-2" aria-label="Versions">
          {versions.data.map((version, index) => (
            <li key={version.version} className="flex items-start gap-2 text-sm">
              <History className="mt-0.5 size-4 shrink-0 text-muted" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="font-medium">Version {version.version}</span>: {version.change}
                <span className="block text-xs text-muted" title={formatDateTime(version.at)}>
                  {who(version.changed_by)}, {formatRelative(version.at)}
                </span>
              </span>
              {isAdmin && index > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  loading={restore.isPending && restore.variables === version.version}
                  onClick={() =>
                    restore.mutate(version.version, {
                      onSuccess: () => toast.success(`Restored version ${version.version}`),
                      onError: (caught) => toast.error(caught.message),
                    })
                  }
                >
                  Restore
                </Button>
              )}
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}
