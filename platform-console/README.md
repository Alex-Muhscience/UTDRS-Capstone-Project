# UTDRS operator console

The app for **platform operators**, the people who run a UTDRS deployment. It is separate from the organisations' dashboard (`../frontend`): operators have their own accounts, outside every organisation, and sign in here, never there.

- **Sign-in:** a password, then always a code from an authenticator app. An operator without an authenticator sets one up at sign-in (a QR code), and gets recovery codes, shown once. A temporary password (a new operator's, or after a reset) must be changed before anything else.
- **Session:** a short token for the platform API only, refreshed while in use. It is kept for the tab (`sessionStorage`). It ends after 30 minutes without use, 8 hours after sign-in, or at sign-out, and the console then returns to the sign-in page saying why.
- **Organisations:** every organisation's people and activity. Create one with its first administrator, add an administrator to one that is locked out, suspend, reactivate or delete one, and set up managed service providers.
- **Operators:** add operators (temporary password shown once), reset one who lost their authenticator, deactivate one. You can never act on yourself, and the last active operator is kept.
- **Audit log:** operators' sign-ins and every action in the console.

The gateway's side is described in [the gateway README](../services/api-gateway/README.md) ("Platform operators").

## Run it

```sh
npm install
npm run dev          # http://localhost:5174, /api proxied to the gateway on :8000
npm run lint && npm run typecheck && npm test && npm run build
```

The first operator comes from the gateway's `PLATFORM_OPERATOR_USERNAME` and `PLATFORM_OPERATOR_PASSWORD` settings. In the Docker stack, the console is at http://localhost:8081 (`operator-console` in `docker-compose.yml`); on Vercel it is its own project, with root directory `platform-console` (see [docs/deploy-render.md](../docs/deploy-render.md)).

Types are generated from the gateway's OpenAPI schema: after the gateway's API changes, run `npm run gen:api` and commit `src/api/schema.d.ts`.
