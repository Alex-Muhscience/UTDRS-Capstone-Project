# UTDRS subprocessors

> **Draft for legal review.** Confirm each provider's own terms, location and transfer mechanism.

Last updated: `[DATE]`

| Provider | What it does | Data | Location |
|---|---|---|---|
| Render Services, Inc. | Runs the gateway and the engine | All Customer Data, in processing | Frankfurt, Germany |
| MongoDB, Inc. (Atlas) | The database | All Customer Data, at rest | `[ATLAS REGION]` |
| Vercel Inc. | Serves the dashboard; counts page views without cookies (Web Analytics) | Dashboard pages (no Customer Data is stored there); page-view statistics | `[CONFIRM]` |
| `[SMTP PROVIDER]` | Delivers notification, report and account emails | Recipients' email addresses; the content of those emails | `[LOCATION]` |
| Cloudflare, Inc. | Answers DNS lookups when an organisation proves it owns a domain for single sign-on | The domain name being checked | Global |

## Only when turned on

| Provider | When | Data |
|---|---|---|
| VirusTotal (Google), AbuseIPDB, AlienVault OTX | If threat-intelligence lookups are enabled (off by default) | Indicators from events: IP addresses, domains and file hashes |

## Not subprocessors

The services an organisation connects (its own Microsoft 365 or Google Workspace) are the
organisation's own: UTDRS reads from and acts in them on its behalf. A deployment's own
backups, kept where its operator chooses, are under that operator's control.
