# UTDRS privacy policy

> **Draft for legal review. Not legal advice.** `[BRACKETED]` items are to be completed.

Last updated: `[DATE]`

This policy explains how `[COMPANY LEGAL NAME]` ("we") handles personal data in UTDRS.

## Two roles

- **For your organisation's security data, we are a processor.** The sign-ins, audit logs,
  email details and other events UTDRS receives about an organisation's people are processed
  for that organisation, on its instructions, under its
  [data processing agreement](data-processing-agreement.md). If you are someone whose activity
  an organisation monitors with UTDRS, that organisation is responsible for it: contact them.
- **For running UTDRS itself, we are the controller**: the accounts people use to sign in, the
  records needed to keep UTDRS secure, and how the dashboard is used. The rest of this policy
  is about that.

## What we collect, and why

| Data | Why | Lawful basis (to be confirmed by counsel) |
|---|---|---|
| Account details: username, name, email address, role, organisation | To provide your account | Contract |
| Password (stored only as a bcrypt hash), passkeys (public keys only), MFA secret (encrypted) | To sign you in securely | Contract |
| Sessions: device and browser description, IP address, times | To keep accounts secure; to let you see and end your sessions | Legitimate interests (security) |
| Audit log: actions taken in UTDRS, by whom, when, from which IP address | Security, accountability, and your organisation's records | Legitimate interests; contract |
| Notification and report emails sent to you | To deliver the notifications you chose | Contract |
| Dashboard usage: page views, without cookies (Vercel Web Analytics) | To understand and improve the service | Legitimate interests |

We do not sell personal data, use it for advertising, or use your organisation's security
data to train models without its agreement.

## How long we keep it

- Account details: while the account exists. Deactivated accounts are kept while your
  organisation exists, because records refer to them, unless erased: on request, an
  administrator can erase a person's name, username, email and sign-in methods, which are
  replaced by placeholders.
- Ended sessions: 30 days after they would have expired.
- The audit log: for the life of your organisation (it is tamper-evident, and trimming it
  would break that); your organisation can export it.
- Backups: 14 days.
- Security data processed for organisations: as each organisation chooses (by default, events
  90 days and closed alerts and cases 365 days), as set out in the DPA.

## Who we share it with

The providers that run UTDRS for us, listed in [subprocessors](subprocessors.md): hosting
(Render), the database (MongoDB Atlas), the dashboard (Vercel), and email delivery
(`[SMTP PROVIDER]`). They process data only on our instructions. We may disclose data if the
law requires it, after checking the request is valid.

## Where it is

UTDRS runs in Frankfurt, Germany (Render), with its database in `[ATLAS REGION]`. Transfers
outside `[YOUR REGION]` are protected by `[TRANSFER MECHANISM, e.g. standard contractual clauses]`.

## Your rights

Depending on where you are, you may have the right to access, correct, delete or export your
personal data, to object to or restrict its processing, and to complain to a data protection
authority. Most account details can be seen and corrected in your profile, and your organisation's
administrators can erase them. For anything
else, contact `[PRIVACY CONTACT]`. If your request concerns your organisation's security
data, we will pass it to your organisation, which decides on it.

## Security

See the security measures in the [data processing agreement](data-processing-agreement.md).

## Contact

`[COMPANY LEGAL NAME]`, `[ADDRESS]`. Privacy: `[PRIVACY CONTACT]`. `[DATA PROTECTION OFFICER OR
EU/UK REPRESENTATIVE, IF REQUIRED]`.
