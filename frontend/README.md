# UTDRS dashboard

The web interface for UTDRS: where an analyst sees what needs attention, triages the alerts raised by the core engine, follows each alert back to the event that triggered it, and keeps the asset inventory and rule catalogue up to date. It talks only to the [API gateway](../services/api-gateway).

![Overview](../docs/screenshots/overview.png)

## What it does

| Page | What you can do | Gateway endpoints |
|---|---|---|
| Overview | Open alerts, critical and high counts, events per hour over 24 hours, latest alerts, pipeline health | `GET /alerts/summary`, `/alerts/`, `/events/recent/`, `/detection/`, `/health/db` |
| Alerts | Filter by status and severity, search, page through alerts | `GET /alerts/`, `/alerts/search/` |
| Alert | Start investigating, resolve, mark false positive, close or reopen with a note; assign to yourself; edit tags; see the engine's detector, MITRE ATT&CK techniques and the linked events | `GET /alerts/{id}`, `PATCH /alerts/{id}/status`, `/assign`, `POST`/`DELETE /alerts/{id}/tags/{tag}` |
| Events | Filter by type, search, see the engine's verdict on each event, send a test event | `GET /events/`, `/events/search/`, `POST /events/` |
| Event | The verdict (threat with a link to its alert, clean, failed, analysing, or not analysed), the event's fields and raw data | `GET /events/{id}` |
| Assets | Inventory with criticality and known vulnerabilities; add assets; add and remove CVEs | `/assets/` endpoints |
| Detection rules | The rule catalogue; create rules; switch a rule between enabled, testing and disabled | `/detection/rules` endpoints |
| Simulations | Plan attack-simulation exercises; start and stop them | `/simulation/` endpoints |
| Profile | Change your name and email, change your password | `PUT /auth/me`, `POST /auth/me/change-password` |
| Users *(administrators)* | Add people (with a temporary password shown once), change roles, deactivate and reactivate accounts, reset passwords | `/users/` endpoints |

Administrators manage users, detection rules and simulations; analysts triage alerts and work with events and assets. The dashboard hides what your role cannot do, and the gateway enforces it. New registrations are analysts, and the sign-in page hides registration when the gateway has it closed. Lists that change on their own (alerts, events, system status) refresh every 15 seconds, and an event page refreshes until the engine's verdict arrives. Pushing new alerts to the browser as they happen is on the [roadmap](../README.md#roadmap).

### Try the detection pipeline

On the Events page, **Send test event** offers two presets: *Shadow copies deleted* (a ransomware preparation step) and *Editor opened* (routine activity). Send the first and the event page shows *Analysing*, then *Threat detected* with a link to a critical alert mapped to [T1490](https://attack.mitre.org/techniques/T1490/). The second comes back clean. Both are real verdicts from the core engine.

![An alert raised by the core engine](../docs/screenshots/alert-triage.png)

## Stack

- **React 19** and **TypeScript 6** (strict), built with **Vite 8**
- **React Router 8** (data router), **TanStack Query 5** for server state, polling and cache invalidation
- **Tailwind CSS 4** with design tokens in CSS variables: a dark theme, a light theme, and *System* to follow the OS
- **openapi-fetch** with types generated from the gateway's OpenAPI schema by **openapi-typescript**, so a request or response that does not match the gateway fails to compile
- **Vitest** and **Testing Library** for unit and page tests, **Playwright** for end-to-end tests against the real services
- **ESLint 10** with typescript-eslint and the React Hooks rules
- Served in production by **nginx** (unprivileged) with a strict Content-Security-Policy

No component library and no chart library: the UI kit (`src/components/ui`) and the activity chart are small and written for this app.

## Run it

Requirements: Node.js 22.22 or later (24 LTS recommended), and a running API gateway. To start the gateway and core engine together, see [Development](../README.md#development) in the main README.

```bash
npm install
npm run dev          # http://localhost:5173
```

The dev server proxies `/api` to the gateway at `http://localhost:8000`; set `UTDRS_GATEWAY_URL` to use another one. For sample data, run `python3 scripts/seed-demo.py` from the repository root with `ADMIN_USERNAME` and `ADMIN_PASSWORD` set to the gateway's administrator.

| Script | |
|---|---|
| `npm run dev` | Development server with hot reload |
| `npm run build` | Typecheck, then build to `dist/` |
| `npm run preview` | Serve `dist/` locally (also proxies `/api`) |
| `npm run lint` | ESLint |
| `npm run typecheck` | TypeScript, no output |
| `npm test` | Unit and page tests (Vitest, jsdom) |
| `npm run test:e2e` | End-to-end tests (Playwright); needs the gateway and engine running |
| `npm run gen:api` | Regenerate `src/api/schema.d.ts` from `../services/api-gateway/openapi.json` |

### Configuration

| Variable | Used by | Default | |
|---|---|---|---|
| `VITE_API_URL` | the built app | empty | Base URL of the gateway. Leave empty when the app is served from the same origin as `/api` (the dev server, `vite preview` and the Docker image all proxy it). When set to another origin, add the dashboard's origin to the gateway's `CORS_ORIGINS` and to the CSP's `connect-src`. |
| `UTDRS_GATEWAY_URL` | dev and preview servers | `http://localhost:8000` | Where `/api` is proxied. |
| `GATEWAY_URL` | Docker image | `http://api-gateway:8000` | Where nginx proxies `/api`. |

## Tests

```bash
npm test                                         # 34 unit and page tests
scripts/run-stack.sh npm --prefix frontend run test:e2e   # from the repository root
```

Page tests render the real router and providers against a stubbed gateway (`src/test/gateway.ts`) and cover sign-in and the return to the page you asked for, expired sessions, alert filtering through the URL, triage requests and assignment, event verdicts, sending a test event, what analysts and administrators each see, user administration and closed registration. The end-to-end tests run in Chromium against the real gateway, core engine and MongoDB: register, send the ransomware event, wait for the engine's alert, investigate, assign and resolve it; and check that a routine event comes back clean. `E2E_BASE_URL` points them at an already running dashboard (the Docker image or a deployment) instead of `vite preview`.

## How it is put together

```
src/
  api/          client.ts (typed client, auth middleware, errors), queries.ts (one hook per use),
                schema.d.ts (generated; do not edit)
  auth/         session storage, AuthProvider, route guards
  app/          router, providers, query client
  components/   ui/ (buttons, badges, cards, form fields, dialog, table, states),
                layout/ (shell, navigation, theme switcher, system status), charts/
  pages/        one folder per area, with page tests in pages/__tests__
  lib/          formatting, constants, URL-backed filters, theme
e2e/            Playwright tests
```

- **Types follow the gateway.** `services/api-gateway/scripts/export_openapi.py` writes the gateway's OpenAPI schema to `services/api-gateway/openapi.json`, and `npm run gen:api` turns it into TypeScript. CI regenerates both and fails if either differs from what is committed, so the dashboard and the gateway cannot drift apart silently.
- **Sessions.** The gateway issues a JWT bearer token. It is kept in `sessionStorage` (it survives a reload, not closing the tab) and sent with every request. When the token expires, or the gateway answers 401, the app signs out and says why. The CSP forbids inline and third-party scripts, which limits what could read the token.
- **Filters live in the URL** (`/alerts?status=open&severity=critical`), so a filtered view can be bookmarked or shared and the back button works.
- **Pagination without totals.** The gateway's list endpoints do not return a count, so each page asks for one more row than it shows to know whether there is a next page.
- **Accessibility.** Native `<dialog>` for modals (focus trap, Escape), labelled form controls, a skip link, focus moved to the page on navigation, visible focus rings, `prefers-reduced-motion` respected.

## Deploy

```bash
docker build -t utdrs-dashboard .
docker run -p 8080:8080 -e GATEWAY_URL=http://your-gateway:8000 utdrs-dashboard
```

The image builds the app with Node 24, then serves it from `nginxinc/nginx-unprivileged` on port 8080 as a non-root user. nginx proxies `/api/` to `GATEWAY_URL`, falls back to `index.html` for client-side routes, caches hashed assets for a year and `index.html` never, and sends a Content-Security-Policy (`script-src 'self'`, no inline scripts), `X-Frame-Options: DENY`, `nosniff` and a strict referrer policy (`nginx.conf.template`, `nginx-security-headers.conf`).

Any static host works too: build with `VITE_API_URL` set to the gateway's public URL, serve `dist/` with a fallback to `index.html`, and allow the dashboard's origin in the gateway's `CORS_ORIGINS`.
