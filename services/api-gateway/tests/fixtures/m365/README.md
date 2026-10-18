# Microsoft Graph samples

Responses in the shape Microsoft Graph v1.0 documents for each API, with made-up
tenants, people and addresses (`contoso.example`, documentation IP ranges). The
Microsoft 365 connector's tests serve these from a stand-in for Microsoft, so the
connector is built and checked against Graph's real formats without a Microsoft 365
tenant. Replace or add to them with records captured from a real tenant (with personal
data removed) as they become available.

- `signins_page1.json`, `signins_page2.json`: `GET /auditLogs/signIns` ([signIn](https://learn.microsoft.com/graph/api/resources/signin)), two pages joined by `@odata.nextLink`.
- `directory_audits.json`: `GET /auditLogs/directoryAudits` ([directoryAudit](https://learn.microsoft.com/graph/api/resources/directoryaudit)).
- `alerts_v2.json`: `GET /security/alerts_v2` ([alert](https://learn.microsoft.com/graph/api/resources/security-alert)).
