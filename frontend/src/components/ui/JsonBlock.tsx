export function JsonBlock({ value, label }: { value: unknown; label: string }) {
  return (
    <pre
      aria-label={label}
      className="max-h-96 overflow-auto rounded-lg border border-border bg-surface-2 p-4 font-mono text-xs leading-relaxed text-muted"
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}
