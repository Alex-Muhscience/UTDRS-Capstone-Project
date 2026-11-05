import { Outlet } from "react-router"

import { NotFoundPage } from "@/pages/errors/NotFoundPage"

import { useIsPlatformAdmin } from "./context"

/** The platform console; for everyone else it does not exist. */
export function RequirePlatformAdmin() {
  return useIsPlatformAdmin() ? <Outlet /> : <NotFoundPage />
}
