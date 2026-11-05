import type { RouteObject } from "react-router"

import { RequireAdmin } from "@/auth/RequireAdmin"
import { RequirePermission } from "@/auth/RequirePermission"
import { RequirePlatformAdmin } from "@/auth/RequirePlatformAdmin"
import { GuestOnly, RequireAuth } from "@/auth/RequireAuth"
import { AppLayout } from "@/components/layout/AppLayout"
import { ApiKeysPage } from "@/pages/admin/ApiKeysPage"
import { AuditLogPage } from "@/pages/admin/AuditLogPage"
import { ConnectorsPage } from "@/pages/connectors/ConnectorsPage"
import { ConsentedPage } from "@/pages/connectors/ConsentedPage"
import { EmailLogPage } from "@/pages/admin/EmailLogPage"
import { RetentionPage } from "@/pages/admin/RetentionPage"
import { RolesPage } from "@/pages/admin/RolesPage"
import { WebhooksPage } from "@/pages/admin/WebhooksPage"
import { AlertDetailPage } from "@/pages/alerts/AlertDetailPage"
import { AlertsPage } from "@/pages/alerts/AlertsPage"
import { AssetDetailPage } from "@/pages/assets/AssetDetailPage"
import { CaseDetailPage } from "@/pages/cases/CaseDetailPage"
import { CasesPage } from "@/pages/cases/CasesPage"
import { AssetsPage } from "@/pages/assets/AssetsPage"
import { ForgotPasswordPage, ResetPasswordPage, VerifyEmailPage } from "@/pages/auth/AccountPages"
import { LoginPage } from "@/pages/auth/LoginPage"
import { SsoCallbackPage } from "@/pages/auth/SsoPages"
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
import { ClientsPage } from "@/pages/msp/ClientsPage"
import { OrganisationPage } from "@/pages/platform/OrganisationPage"
import { PlatformPage } from "@/pages/platform/PlatformPage"
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
          { path: "/forgot-password", element: <ForgotPasswordPage /> },
          { path: "/reset-password", element: <ResetPasswordPage /> },
          { path: "/sso/callback", element: <SsoCallbackPage /> },
        ],
      },
      // Signed in or not: the link is opened from an email.
      { path: "/verify-email", element: <VerifyEmailPage /> },
      {
        element: <RequireAuth />,
        children: [
          {
            element: <AppLayout />,
            children: [
              { index: true, element: <OverviewPage /> },
              { path: "get-started", element: <GetStartedPage /> },
              {
                element: <RequirePermission permission="cases:read" label="cases" />,
                children: [
                  { path: "cases", element: <CasesPage /> },
                  { path: "cases/:caseId", element: <CaseDetailPage /> },
                ],
              },
              {
                element: <RequirePermission permission="response:read" label="response actions" />,
                children: [
                  { path: "response", element: <ResponsePage /> },
                ],
              },
              {
                element: <RequirePermission permission="playbooks:read" label="playbooks" />,
                children: [
                  { path: "playbooks", element: <PlaybooksPage /> },
                ],
              },
              {
                element: <RequirePermission permission="reports:read" label="reports" />,
                children: [
                  { path: "reports", element: <ReportsPage /> },
                  { path: "reports/:reportId", element: <ReportPage /> },
                ],
              },
              {
                element: <RequirePermission permission="alerts:read" label="alerts" />,
                children: [
                  { path: "alerts", element: <AlertsPage /> },
                  { path: "alerts/:alertId", element: <AlertDetailPage /> },
                ],
              },
              {
                element: <RequirePermission permission="events:read" label="events" />,
                children: [
                  { path: "events", element: <EventsPage /> },
                  { path: "events/:eventId", element: <EventDetailPage /> },
                ],
              },
              {
                element: <RequirePermission permission="assets:read" label="assets" />,
                children: [
                  { path: "assets", element: <AssetsPage /> },
                  { path: "assets/:assetId", element: <AssetDetailPage /> },
                ],
              },
              {
                element: <RequirePermission permission="rules:read" label="detection rules" />,
                children: [
                  { path: "rules", element: <RulesPage /> },
                  { path: "rules/:ruleId", element: <RuleDetailPage /> },
                ],
              },
              {
                element: <RequirePermission permission="simulations:read" label="simulations" />,
                children: [
                  { path: "simulations", element: <SimulationsPage /> },
                ],
              },
              {
                element: <RequirePermission permission="tuning:read" label="tuning" />,
                children: [
                  { path: "tuning", element: <TuningPage /> },
                ],
              },
              { path: "profile", element: <ProfilePage /> },
              { path: "clients", element: <ClientsPage /> },
              {
                element: <RequirePlatformAdmin />,
                children: [
                  { path: "platform", element: <PlatformPage /> },
                  { path: "platform/organisations/:tenantId", element: <OrganisationPage /> },
                ],
              },
              {
                element: <RequireAdmin />,
                children: [
                  { path: "users", element: <UsersPage /> },
                  { path: "roles", element: <RolesPage /> },
                  { path: "api-keys", element: <ApiKeysPage /> },
                  { path: "audit-log", element: <AuditLogPage /> },
                  { path: "email-log", element: <EmailLogPage /> },
                  { path: "retention", element: <RetentionPage /> },
                  { path: "webhooks", element: <WebhooksPage /> },
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
