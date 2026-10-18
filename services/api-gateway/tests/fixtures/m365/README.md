# Microsoft Graph samples

Responses in the shape Microsoft documents for each API (Graph v1.0, and the Office 365 Management Activity API), with made-up
tenants, people and addresses (`contoso.example`, documentation IP ranges). The
Microsoft 365 connector's tests serve these from a stand-in for Microsoft, so the
connector is built and checked against Graph's real formats without a Microsoft 365
tenant. Replace or add to them with records captured from a real tenant (with personal
data removed) as they become available.

- `signins_page1.json`, `signins_page2.json`: `GET /auditLogs/signIns` ([signIn](https://learn.microsoft.com/graph/api/resources/signin)), two pages joined by `@odata.nextLink`.
- `directory_audits.json`: `GET /auditLogs/directoryAudits` ([directoryAudit](https://learn.microsoft.com/graph/api/resources/directoryaudit)).
- `alerts_v2.json`: `GET /security/alerts_v2` ([alert](https://learn.microsoft.com/graph/api/resources/security-alert)), naming a phishing message (`analyzedMessageEvidence`).
- `message.json` and `message_attachments.json`: that message, `GET /users/{id}/messages?$filter=internetMessageId eq '...'` ([message](https://learn.microsoft.com/graph/api/resources/message)), and its attachment ([fileAttachment](https://learn.microsoft.com/graph/api/resources/fileattachment)).
- `exchange_content.json`: the Office 365 Management Activity API's `GET /subscriptions/content?contentType=Audit.Exchange` ([available content](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-reference#list-available-content)).
- `exchange_audit.json`: one content blob from that list: Exchange audit records ([schema](https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema#exchange-admin-schema)): an inbox rule forwarding outside and hiding mail, a rule forwarding inside, mailbox forwarding outside, and two records UTDRS does not keep.
