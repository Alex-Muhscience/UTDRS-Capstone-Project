import { useMemo } from "react"

import { formatTime } from "@/lib/format"

const HOUR = 3600_000

/** Events per hour over the `hours` hours up to `now`, as an SVG bar chart. */
export function ActivityChart({ timestamps, now, hours = 24 }: { timestamps: string[]; now: number; hours?: number }) {
  const buckets = useMemo(() => {
    const end = Math.ceil(now / HOUR) * HOUR
    const start = end - hours * HOUR
    const counts = Array.from({ length: hours }, (_, index) => ({ start: start + index * HOUR, count: 0 }))
    for (const timestamp of timestamps) {
      const time = new Date(timestamp).getTime()
      if (time < start || time >= end) continue
      const bucket = counts[Math.floor((time - start) / HOUR)]
      if (bucket) bucket.count += 1
    }
    return counts
  }, [timestamps, hours, now])

  const max = Math.max(1, ...buckets.map((bucket) => bucket.count))
  const width = 600
  const height = 140
  const gap = 4
  const barWidth = width / buckets.length - gap
  const total = buckets.reduce((sum, bucket) => sum + bucket.count, 0)

  return (
    <figure>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-40 w-full"
        role="img"
        aria-label={`${total} events in the last ${hours} hours, at most ${max} in one hour`}
        preserveAspectRatio="none"
      >
        {[0.25, 0.5, 0.75, 1].map((fraction) => (
          <line
            key={fraction}
            x1={0}
            x2={width}
            y1={height - height * fraction}
            y2={height - height * fraction}
            className="stroke-border"
            strokeDasharray="3 5"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {buckets.map((bucket, index) => {
          const barHeight = bucket.count ? Math.max(3, (bucket.count / max) * (height - 8)) : 0
          const x = index * (barWidth + gap) + gap / 2
          return (
            <g key={bucket.start}>
              <rect
                x={x}
                y={height - barHeight}
                width={barWidth}
                height={barHeight}
                rx={2}
                className="fill-accent/70 transition-colors hover:fill-accent"
              >
                <title>{`${formatTime(new Date(bucket.start))}: ${bucket.count} event${bucket.count === 1 ? "" : "s"}`}</title>
              </rect>
            </g>
          )
        })}
      </svg>
      <div className="relative mt-2 h-4 text-[11px] text-subtle" aria-hidden>
        {buckets.map((bucket, index) =>
          index % 6 === 0 ? (
            <span key={bucket.start} className="absolute" style={{ left: `${(index / buckets.length) * 100}%` }}>
              {formatTime(new Date(bucket.start))}
            </span>
          ) : null,
        )}
      </div>
    </figure>
  )
}
