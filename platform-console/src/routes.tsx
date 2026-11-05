import type { RouteObject } from "react-router"

import { Layout } from "@/components/Layout"
import { AuditLogPage } from "@/pages/AuditLogPage"
import { NotFoundPage } from "@/pages/NotFoundPage"
import { OperatorsPage } from "@/pages/OperatorsPage"
import { OrganisationPage } from "@/pages/OrganisationPage"
import { OrganisationsPage } from "@/pages/OrganisationsPage"
import { SignInPage } from "@/pages/SignInPage"

export const routes: RouteObject[] = [
  { path: "/sign-in", element: <SignInPage /> },
  {
    element: <Layout />,
    children: [
      { index: true, element: <OrganisationsPage /> },
      { path: "organisations/:tenantId", element: <OrganisationPage /> },
      { path: "operators", element: <OperatorsPage /> },
      { path: "audit-log", element: <AuditLogPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]
