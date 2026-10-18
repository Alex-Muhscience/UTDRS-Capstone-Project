# Deploying the backend on Render

The dashboard is on Vercel (built from this repository). This puts the backend on [Render](https://render.com) and the database on [MongoDB Atlas](https://www.mongodb.com/atlas), from `render.yaml`:

| Piece | Where | Address |
|---|---|---|
| Dashboard | Vercel | https://utdrs-capstone-project.vercel.app |
| API gateway | Render web service `utdrs-api-gateway` | https://utdrs-api-gateway.onrender.com |
| Core engine | Render web service `utdrs-core-engine` | https://utdrs-core-engine.onrender.com (answers only the gateway: it needs the shared internal token) |
| Database | MongoDB Atlas | databases `utdrs` (gateway) and `utdrs_engine` (engine) in one cluster |

The browser calls the gateway directly (its address is in `frontend/.env.vercel`, read by `vite.config.ts` only in Vercel builds, so nothing in the Vercel project's settings can override it), and the gateway allows the dashboard's origins (CORS), so the gateway sees each person's real address for sign-in throttling. `frontend/vercel.json` also serves the app for every route and sends the same security headers as the Docker image.

## 1. The database: MongoDB Atlas

1. Create a free **M0** cluster, on AWS in Frankfurt (`eu-central-1`), next to the Render region in `render.yaml`.
2. **Database Access**: add a database user with a long random password, role *Read and write to any database*.
3. **Network Access**: add `0.0.0.0/0`. Render's free and starter services have no fixed outgoing address; the strong password is what protects the database. (On Render's paid plans with static outbound IPs, list those instead.)
4. **Connect > Drivers**: copy the connection string, `mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority`, with your password in it.

## 2. The backend: a Render Blueprint

1. Sign in to Render with GitHub, and allow it to read this repository.
2. **New > Blueprint**, choose the repository and the `main` branch. Render reads `render.yaml` and lists the engine, the gateway and the shared group of settings.
3. Fill in what it asks for:
   - `MONGODB_URI`, for both services: the Atlas connection string (the same one).
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD`: the first administrator (user name `admin`). Use a password manager; at least 8 characters.
4. **Apply**. The engine builds first (a few minutes: it installs its machine-learning libraries), then the gateway. Render generates `JWT_SECRET`, `ENCRYPTION_KEY` and the shared `INTERNAL_API_TOKEN`.
5. Check both service addresses in Render. If either name was taken, Render adds a suffix: then change the addresses in `render.yaml` (`CORE_ENGINE_URL`), `frontend/.env.vercel` (`UTDRS_DEPLOY_API_URL`) and `frontend/vercel.json` (`connect-src`), and push.

## 3. Check it

- https://utdrs-api-gateway.onrender.com/api/v1/health answers `{"status":"ok"}`, and `/api/v1/detection/` shows the engine reachable (sign in first; or look for "Sent N rules to the core engine" in the gateway's Render logs).
- Open the dashboard, sign in as `admin`, and send a test event (Events > Send test event): "Shadow copies deleted" becomes an alert.
- Audit log: your sign-in shows your own public address. If it shows a `10.x` or Render address instead, Render's proxies are not in `TRUSTED_PROXIES`; tell us what it shows.
- Then: Profile > set up multi-factor authentication, and require it for everyone.

## Keep safe

- **`ENCRYPTION_KEY`** (gateway > Environment): copy it to a password manager. Without it, stored secrets (Microsoft 365 credentials, MFA, webhook secrets) cannot be read; people would have to set MFA up again. To change it, set the old value as `ENCRYPTION_KEY_PREVIOUS`.
- `JWT_SECRET`: changing it signs everyone out, nothing worse.
- Atlas: turn on backups when you leave the free tier.

## Free plan, and when to upgrade

`render.yaml` uses Render's **free** plan, which is fine to try it out:

- A free service **sleeps after 15 minutes without requests**; the next request wakes it, taking about a minute. While the gateway sleeps, its scheduled work pauses: Microsoft 365 polling, email, monthly reports, retention, webhooks. While the engine sleeps, the first event analysed after it wakes can time out (it is marked as an analysis error; later events are fine).
- Free services cannot use Render's private network, so the gateway calls the engine at its public address (protected by the internal token).
- 512 MB of memory: the gateway runs 2 workers (`WEB_CONCURRENCY`).

For real use, change `plan: free` to `plan: starter` (or larger) for both services. On a paid plan you can also move the engine to the private network: in `render.yaml`, give `CORE_ENGINE_URL` `fromService: {type: web, name: utdrs-core-engine, property: hostport}` instead of `value`, or make the engine a private service (`type: pserv`).

## Optional

- **Email**: in the gateway's environment, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM` (see `.env.example`).
- **Microsoft 365 "Connect with Microsoft"**: `M365_CLIENT_ID` and `M365_CLIENT_SECRET` of your multi-tenant app registration, with `https://utdrs-capstone-project.vercel.app/connectors/microsoft-365/consented` as a redirect URI. Organisations can always connect with their own app registration without these.
- **Self-service sign-up** (each new account a new organisation): `ALLOW_REGISTRATION=true` (`REGISTRATION_MODE` is already `organisation`).
- **The MCP server** for AI assistants: uncomment `utdrs-mcp-server` in `render.yaml`; clients connect to `https://utdrs-mcp-server.onrender.com/mcp` with a UTDRS API key.
- **The scanner** (device inventory over mutual TLS) is not part of this deployment; it needs a TCP port and certificates (see `scanner/`).
