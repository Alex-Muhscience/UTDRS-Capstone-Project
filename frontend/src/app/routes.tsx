import type { RouteObject } from "react-router"

import { RequireAdmin } from "@/auth/RequireAdmin"
import { GuestOnly, RequireAuth } from "@/auth/RequireAuth"
import { AppLayout } from "@/components/layout/AppLayout"
import { ApiKeysPage } from "@/pages/admin/ApiKeysPage"
import { AuditLogPage } from "@/pages/admin/AuditLogPage"
import { ConnectorsPage } from "@/pages/connectors/ConnectorsPage"
import { ConsentedPage } from "@/pages/connectors/ConsentedPage"
import { EmailLogPage } from "@/pages/admin/EmailLogPage"
import { RetentionPage } from "@/pages/admin/RetentionPage"
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
import { GetStartedPage } from "@/pages/onboarding/GetStartedPage"
import { OverviewPage } from "@/pages/overview/OverviewPage"
import { ProfilePage } from "@/pages/profile/ProfilePage"
import { ReportPage } from "@/pages/reports/ReportPage"
import { ReportsPage } from "@/pages/reports/ReportsPage"
import { PlaybooksPage } from "@/pages/response/PlaybooksPage"
import { ResponsePage } from "@/pages/response/ResponsePage"
import { RuleDetailPage } from "@/pages/rules/RuleDetailPage"
import { RulesPage } from "@/pages/rules/RulesPage"
import { SimulationsPage } from "@/pages/simulations/SimulationsPage"
import { TuningPage } from "@/pages/tuning/TuningPage"
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
              { path: "get-started", element: <GetStartedPage /> },
              { path: "cases", element: <CasesPage /> },
              { path: "cases/:caseId", element: <CaseDetailPage /> },
              { path: "response", element: <ResponsePage /> },
              { path: "playbooks", element: <PlaybooksPage /> },
              { path: "reports", element: <ReportsPage /> },
              { path: "reports/:reportId", element: <ReportPage /> },
              { path: "alerts", element: <AlertsPage /> },
              { path: "alerts/:alertId", element: <AlertDetailPage /> },
              { path: "events", element: <EventsPage /> },
              { path: "events/:eventId", element: <EventDetailPage /> },
              { path: "assets", element: <AssetsPage /> },
              { path: "assets/:assetId", element: <AssetDetailPage /> },
              { path: "rules", element: <RulesPage /> },
              { path: "rules/:ruleId", element: <RuleDetailPage /> },
              { path: "simulations", element: <SimulationsPage /> },
              { path: "tuning", element: <TuningPage /> },
              { path: "profile", element: <ProfilePage /> },
              {
                element: <RequireAdmin />,
                children: [
                  { path: "users", element: <UsersPage /> },
                  { path: "api-keys", element: <ApiKeysPage /> },
                  { path: "audit-log", element: <AuditLogPage /> },
                  { path: "email-log", element: <EmailLogPage /> },
                  { path: "retention", element: <RetentionPage /> },
                  { path: "connectors", element: <ConnectorsPage /> },
                  { path: "connectors/microsoft-365/consented", element: <ConsentedPage /> },
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
