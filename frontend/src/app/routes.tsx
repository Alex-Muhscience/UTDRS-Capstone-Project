import type { RouteObject } from "react-router"

import { RequireAdmin } from "@/auth/RequireAdmin"
import { GuestOnly, RequireAuth } from "@/auth/RequireAuth"
import { AppLayout } from "@/components/layout/AppLayout"
import { ApiKeysPage } from "@/pages/admin/ApiKeysPage"
import { AuditLogPage } from "@/pages/admin/AuditLogPage"
import { AlertDetailPage } from "@/pages/alerts/AlertDetailPage"
import { AlertsPage } from "@/pages/alerts/AlertsPage"
import { AssetDetailPage } from "@/pages/assets/AssetDetailPage"
import { CaseDetailPage } from "@/pages/cases/CaseDetailPage"
import { CasesPage } from "@/pages/cases/CasesPage"
import { AssetsPage } from "@/pages/assets/AssetsPage"
import { LoginPage } from "@/pages/auth/LoginPage"
import { RegisterPage } from "@/pages/auth/RegisterPage"
import { RouteError } from "@/pages/errors/RouteError"
import { NotFoundPage } from "@/pages/errors/NotFoundPage"
import { EventDetailPage } from "@/pages/events/EventDetailPage"
import { EventsPage } from "@/pages/events/EventsPage"
import { OverviewPage } from "@/pages/overview/OverviewPage"
import { ProfilePage } from "@/pages/profile/ProfilePage"
import { RuleDetailPage } from "@/pages/rules/RuleDetailPage"
import { RulesPage } from "@/pages/rules/RulesPage"
import { SimulationsPage } from "@/pages/simulations/SimulationsPage"
import { UsersPage } from "@/pages/users/UsersPage"

export const routes: RouteObject[] = [
  {
    errorElement: <RouteError />,
    children: [
      {
        element: <GuestOnly />,
        children: [
          { path: "/login", element: <LoginPage /> },
          { path: "/register", element: <RegisterPage /> },
        ],
      },
      {
        element: <RequireAuth />,
        children: [
          {
            element: <AppLayout />,
            children: [
              { index: true, element: <OverviewPage /> },
              { path: "cases", element: <CasesPage /> },
              { path: "cases/:caseId", element: <CaseDetailPage /> },
              { path: "alerts", element: <AlertsPage /> },
              { path: "alerts/:alertId", element: <AlertDetailPage /> },
              { path: "events", element: <EventsPage /> },
              { path: "events/:eventId", element: <EventDetailPage /> },
              { path: "assets", element: <AssetsPage /> },
              { path: "assets/:assetId", element: <AssetDetailPage /> },
              { path: "rules", element: <RulesPage /> },
              { path: "rules/:ruleId", element: <RuleDetailPage /> },
              { path: "simulations", element: <SimulationsPage /> },
              { path: "profile", element: <ProfilePage /> },
              {
                element: <RequireAdmin />,
                children: [
                  { path: "users", element: <UsersPage /> },
                  { path: "api-keys", element: <ApiKeysPage /> },
                  { path: "audit-log", element: <AuditLogPage /> },
                ],
              },
              { path: "*", element: <NotFoundPage /> },
            ],
          },
        ],
      },
    ],
  },
]
