import qrcode from "qrcode-generator"
import { useMemo } from "react"

/** A QR code for `value`, drawn as SVG from the code's modules (no generated markup is inserted). */
export function QrCode({ value, label, size = 176 }: { value: string; label: string; size?: number }) {
  const { count, cells } = useMemo(() => {
    const qr = qrcode(0, "M")
    qr.addData(value)
    qr.make()
    const count = qr.getModuleCount()
    const cells: Array<[number, number]> = []
    for (let row = 0; row < count; row++) {
      for (let col = 0; col < count; col++) if (qr.isDark(row, col)) cells.push([col, row])
    }
    return { count, cells }
  }, [value])
  const margin = 2
  const extent = count + margin * 2
  return (
    <svg role="img" aria-label={label} width={size} height={size} viewBox={`0 0 ${extent} ${extent}`} shapeRendering="crispEdges" className="rounded-lg bg-white">
      <path d={cells.map(([x, y]) => `M${x + margin} ${y + margin}h1v1h-1z`).join("")} fill="#000" />
    </svg>
  )
}
