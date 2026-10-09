import { Outlet } from "react-router"

import { NotFoundPage } from "@/pages/errors/NotFoundPage"

import { useIsAdmin } from "./context"

/** Pages for administrators; others see "not found", as for any page they cannot use. */
export function RequireAdmin() {
  return useIsAdmin() ? <Outlet /> : <NotFoundPage />
}
