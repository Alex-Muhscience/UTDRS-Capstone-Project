export function Logo({ compact }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <svg viewBox="0 0 32 32" className="size-7 shrink-0" aria-hidden>
        <rect width="32" height="32" rx="8" className="fill-accent/15" />
        <path
          d="M16 6l8.5 3.3v6.4c0 5.2-3.6 9.4-8.5 11-4.9-1.6-8.5-5.8-8.5-11V9.3L16 6z"
          fill="none"
          className="stroke-accent"
          strokeWidth="2"
          strokeLinejoin="round"
        />
        <path d="M12 16.2l2.8 2.8 5.3-5.6" fill="none" className="stroke-fg" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {!compact && (
        <span className="leading-tight">
          <span className="block text-sm font-semibold tracking-wide">UTDRS</span>
          <span className="block text-[11px] text-subtle">Threat detection &amp; response</span>
        </span>
      )}
      {compact && <span className="text-sm font-semibold tracking-wide">UTDRS</span>}
    </span>
  )
}
