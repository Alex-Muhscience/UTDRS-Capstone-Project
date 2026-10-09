import { ButtonLink } from "@/components/ui/Button"

export function NotFoundPage() {
  return (
    <div className="grid place-items-center py-24 text-center">
      <p className="font-mono text-sm text-accent">404</p>
      <h1 className="mt-2 text-xl font-semibold">Page not found</h1>
      <p className="mt-2 text-sm text-muted">The page you asked for does not exist.</p>
      <ButtonLink to="/" variant="primary" className="mt-6">
        Back to the overview
      </ButtonLink>
    </div>
  )
}
