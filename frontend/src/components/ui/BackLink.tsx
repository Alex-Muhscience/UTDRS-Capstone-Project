import { ArrowLeft } from "lucide-react"
import { Link } from "react-router"

export function BackLink({ to, children }: { to: string; children: string }) {
  return (
    <Link to={to} className="inline-flex items-center gap-1.5 text-xs font-medium text-muted hover:text-fg">
      <ArrowLeft className="size-3.5" aria-hidden />
      {children}
    </Link>
  )
}
