# UTDRS data processing agreement

> **Draft for legal review. Not legal advice.** `[BRACKETED]` items are to be completed.
> Counsel should check it against the law that applies (for example Article 28 of the EU GDPR)
> and attach the transfer clauses needed.

Between the organisation that uses UTDRS (the **controller**, "you") and `[COMPANY LEGAL NAME]`
(the **processor**, "we"). It forms part of the [terms of service](terms-of-service.md).

## 1. Subject and duration

We process personal data in Customer Data only to provide UTDRS to you, for as long as you
use it, and then until it is deleted as in section 9. The details are in Annex 1.

## 2. Your instructions

We process personal data only on your documented instructions: these terms, and what you
configure in UTDRS (the services you connect, retention periods, playbooks and response
modes, notification recipients). We tell you if we believe an instruction breaks the law.

## 3. Confidentiality

Everyone we authorise to process the data is bound to confidentiality.

## 4. Security

We apply the measures in Annex 2, and keep them appropriate to the risk.

## 5. Subprocessors

You authorise the subprocessors listed in [subprocessors](subprocessors.md). We will tell
you `[30]` days before adding or replacing one; you may object on reasonable data protection
grounds, and if we cannot resolve it, end the affected service. We impose on each
subprocessor data protection obligations equivalent to these, and remain liable for them.

## 6. Helping you

Taking into account the nature of the processing, we help you respond to requests from
people exercising their rights, and with security, impact assessments and consultations
with authorities. Much of this is self-service in UTDRS (exporting the audit log, retention
settings, deactivating accounts); for the rest, contact `[PRIVACY CONTACT]`.

## 7. Personal data breaches

We notify you without undue delay, and within `[48]` hours of becoming aware of a personal
data breach affecting Customer Data, with what we know then (its nature, the data and people
concerned, likely consequences, measures taken) and updates as we learn more.

## 8. Transfers

Customer Data is hosted as in Annex 1. Transfers to a country without adequate protection are
made only with appropriate safeguards: `[STANDARD CONTRACTUAL CLAUSES / OTHER MECHANISM]`.

## 9. Deletion and return

During the subscription you control retention, and can export the audit log. When the
subscription ends, you may export Customer Data for `[30]` days; then we delete it from the
service, and from backups as they expire (within 14 days), unless the law requires us to
keep it.

## 10. Audits

We make available the information needed to show compliance with this agreement, and allow
audits by you or an auditor you appoint, `[ONCE A YEAR, ON 30 DAYS' NOTICE, AT YOUR COST]`,
or more often after a breach.

---

## Annex 1: details of the processing

| | |
|---|---|
| **Purpose** | Detecting, investigating and responding to security threats to your organisation |
| **Nature** | Collecting events from connected services and sources, analysing them automatically (rules, correlations, machine-learning models), storing alerts and cases, notifying people you choose, and taking the response actions you configure |
| **People concerned** | Your users of UTDRS; the people whose accounts, devices and email your connected services report on (typically your staff); the senders and recipients of email UTDRS checks |
| **Personal data** | Names, usernames and email addresses; sign-in records (time, IP address, approximate location, device, application, outcome, risk); administrative actions; app authorisations; file sharing records (file titles, who it was shared with); email details (sender, recipients, subject, authentication results, link domains, attachment names, types and hashes); case notes and files your analysts attach; IP addresses and device names from device scans |
| **Special categories** | Not intended. Case notes and attached files could contain any data; you control what is attached |
| **Email bodies** | Read to judge phishing, then not kept: neither the gateway nor the engine stores the body |
| **Retention** | As you set it per kind of data (defaults: events 90 days, closed alerts, cases and response actions 365 days, notifications 90 days, analysts' verdict labels 730 days, at most 730 days for any); the engine's own copy of events 30 days; open cases and their alerts and events are kept while open; the audit log for the life of your organisation; backups 14 days |
| **Location** | Application servers in Frankfurt, Germany (Render); database in `[ATLAS REGION]` (MongoDB Atlas); dashboard served by Vercel |

## Annex 2: security measures

Each describes what UTDRS does now.

**Access**
- Accounts with roles (administrator, analyst); API keys with scopes, never administrators.
- Multi-factor authentication (authenticator codes, recovery codes, passkeys), which an
  organisation can require; single sign-on (OpenID Connect, SAML) with domains proven by DNS.
- Sessions: 15-minute access tokens, single-use refresh tokens with reuse detection, idle and
  absolute time limits, sign-out everywhere by the person or an administrator.
- Sign-in throttling per account and address; password reset links single-use and short-lived.

**Separation**
- Every record belongs to one organisation, and every query is scoped to it in one place,
  in the gateway and in the engine; tested.

**Encryption**
- In transit: HTTPS between users, the dashboard, the gateway and the engine.
- At rest: connector credentials, SSO client secrets and MFA secrets encrypted with AES-GCM,
  bound to their organisation, with key rotation; passwords, API keys, tokens and recovery
  codes stored only as hashes; database storage encrypted by the hosting provider
  `[CONFIRM FOR YOUR ATLAS TIER]`.

**Accountability**
- A hash-chained audit log of sign-ins and every change, verifiable, exportable, and checkable
  outside UTDRS.

**Resilience**
- Daily backups, each checked and restore-tested, kept 14 days; health monitoring of every
  background process, with alerts to operators.

**Minimisation**
- Email bodies are not stored. Files attached to cases are served only as downloads.

**Development**
- Every change is tested before release; dependencies are kept current.
