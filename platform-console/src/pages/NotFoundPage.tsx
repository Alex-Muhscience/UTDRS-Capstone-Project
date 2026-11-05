import { ButtonLink } from "@/components/ui/Button"

export function NotFoundPage() {
  return (
    <div className="grid place-items-center py-24 text-center">
      <h1 className="text-xl font-semibold">Page not found</h1>
      <ButtonLink to="/" variant="primary" className="mt-6">
        Back to organisations
      </ButtonLink>
    </div>
  )
}
