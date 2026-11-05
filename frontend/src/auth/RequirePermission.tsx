import { Outlet } from "react-router"

import { ButtonLink } from "@/components/ui/Button"

import { useCan } from "./context"

/** Pages of an area the person's role may not see say so, rather than failing request by request. */
export function RequirePermission({ permission, label }: { permission: string; label: string }) {
  if (useCan(permission)) return <Outlet />
  return (
    <div className="grid place-items-center py-24 text-center">
      <h1 className="text-xl font-semibold">Not part of your role</h1>
      <p className="mt-2 text-sm text-muted">Your role does not include {label}. Ask an administrator if you need it.</p>
      <ButtonLink to="/" variant="primary" className="mt-6">
        Back to the overview
      </ButtonLink>
    </div>
  )
}
