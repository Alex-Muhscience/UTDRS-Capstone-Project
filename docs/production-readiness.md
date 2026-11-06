# Production readiness

A review of the hosted deployment (Render, Vercel and MongoDB Atlas) on 6 November 2026, and what remains before real organisations rely on it. The live checks below were run against https://utdrs-api-gateway-1pjf.onrender.com and https://utdrs-capstone-project.vercel.app.

## Before real customers

These stop UTDRS from working as a security service, or put data at risk.

| # | What | Why | What to do |
|---|---|---|---|
| 1 | **Hosting plan.** Both Render services are on the free plan. | Free services sleep after 15 minutes without traffic and take about a minute to wake. While the gateway sleeps, nothing in the background runs: Microsoft 365 and Google Workspace are not polled, queued events are not analysed, webhooks and emails are not sent, monthly reports and retention do not run, and the health checks that alert you stop too. Free instances also have 512 MB of memory, tight for the core engine's models. | Move both services to Render's **Starter** plan or above (`plan: starter` in `render.yaml`, or in the Render dashboard). |
| 2 | **Database backups.** Atlas M0 has no backups, and holds at most 512 MB. | A mistake, a bug or an attacker could lose every organisation's data for good. | Either move to **Atlas M10** or above and turn on continuous backups, or turn on the daily off-site backup job: a bucket (Cloudflare R2's free tier is enough), a passphrase, and the `utdrs-backup` cron job in `render.yaml` (steps in `ops/backup/README.md`). Then fetch one and do a restore test. |
| 3 | **Atlas password.** It was shared in a conversation earlier. | Anyone who saw it can read and change every organisation's data. | Rotate it in Atlas (Database Access), then update `MONGODB_URI` on both Render services. |
| 4 | **Email.** No `SMTP_*` settings are configured. | People cannot reset forgotten passwords or confirm their addresses, and nobody is emailed about new cases, approvals, reports, or the platform's own problems. | Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` and `OPERATOR_EMAILS` on the gateway (any SMTP provider: SendGrid, Mailgun, Amazon SES, Postmark). Then send a test from the dashboard. |
| 5 | **Latest version, and the operator console.** The live gateway does not yet have the operator sign-in (`/api/v1/platform/auth/login` answers 404). The operator console's Vercel project does not exist yet. | Until then, nobody can use the platform console: the old way in has been removed. | In Render, check the gateway deployed the latest `main` (Manual Deploy if not). Set `PLATFORM_OPERATOR_USERNAME`, `PLATFORM_OPERATOR_EMAIL` and `PLATFORM_OPERATOR_PASSWORD`. Create the Vercel project with root directory `platform-console` (docs/deploy-render.md, step 3). Then sign in and set up the authenticator. |
| 6 | **Continuous integration.** The recent changes were tested on a developer machine, because the GitHub Actions minutes ran out. | The full pipeline (system test, end-to-end tests, the Docker stack) has not run on them. | When the minutes reset, re-run CI on `main` and fix anything it finds before launch. |
| 7 | **Legal documents.** The terms, privacy notice and data processing agreement are drafts. | Organisations will send personal data (their staff's sign-ins and emails). | Have a lawyer review them, then publish them. |

## Strongly recommended

- **Uptime monitoring from outside.** Point a monitor (Better Stack, UptimeRobot, Pingdom) at `https://<gateway>/api/v1/health/ready`. It answers 200 when serving and 503 when the database is unreachable, and accepts `HEAD`. Have it alert a phone, not only email.
- **Multi-factor authentication** for the default organisation. Profile > set it up, then require it for everyone.
- **Your own domains** for the dashboard, operator console and API (for example `app.`, `ops.` and `api.` under your domain). Then update `frontend/src/api/deployment.ts`, `platform-console/src/api/deployment.ts`, both `vercel.json` files (`connect-src`), and the gateway's `CORS_ORIGINS`, `DASHBOARD_URL` and `GATEWAY_URL`.
- **`GATEWAY_URL` and `DASHBOARD_URL`** set to the public addresses. SAML sign-in needs the first; links in emails and webhooks need the second.
- **`ENCRYPTION_KEY`** copied to a password manager. Without it, stored secrets cannot be read: Microsoft 365 credentials, authenticator secrets and webhook secrets.
- **The operator console** additionally protected: Vercel Deployment Protection on that project only, or a domain only your team knows.
- **API documentation.** `/api/v1/docs` and `/api/v1/openapi.json` are public, which helps integrators. Set `API_DOCS=false` on the gateway to hide them.
- **Connectors tested against real tenants.** The Microsoft 365 connector was built against Microsoft's documented formats but has not run against a live tenant. Try it with a test tenant before offering it.
- **Growth.** When one gateway is not enough, add Redis and analysis workers (commented in `render.yaml`).

## Checked live, 6 November 2026

| Check | Result |
|---|---|
| Gateway health and readiness | `ok`, database connected, no platform problems reported |
| Dashboard security headers | Complete: CSP (only the gateway may be called), HSTS, `X-Frame-Options: DENY`, `nosniff`, referrer and permissions policies |
| CORS | Only the dashboard's origins are allowed; an unknown origin is refused |
| Unauthenticated requests | 401, with nothing about the system in the answer |
| Error responses | Validation errors name the field only; no stack traces or internal details |
| Live updates stream | Deployed, and requires sign-in |

Fixed alongside this review:

- The gateway now sends **HSTS** on every response, and the retired `X-XSS-Protection` filter is turned off (`0`), as current guidance advises.
- The health checks accept **`HEAD`**, which many uptime monitors use.
- `/api/v1/health/db` and `/api/v1/health/ready` no longer show the database's error message to the public. It goes to the logs.
- **`API_DOCS`** setting: whether the API documentation is public.

## Already in place

- Organisations' data kept apart in one place, and tested.
- Sessions with short tokens, idle and absolute limits, and signing out anywhere.
- MFA, passkeys, SSO (OIDC and SAML) and SCIM.
- Read-only and custom roles.
- Service providers.
- Platform operators separate from every organisation, with their own console and a mandatory authenticator.
- A hash-chained audit log per organisation and for the platform.
- Encrypted secrets.
- Sign-in throttling.
- Data retention and erasure.
- Webhooks with signatures.
- Metrics and platform health alerts.
- Backups with restore tests (once scheduled, item 2).
