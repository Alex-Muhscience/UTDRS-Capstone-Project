# Legal documents: drafts for review

> **Drafts, not legal advice.** These were written from what UTDRS actually does (the data it
> collects, where it goes, how long it is kept), as starting points for a qualified lawyer.
> Do not publish or rely on them until a lawyer in your jurisdiction has reviewed them.

| Document | For | Status |
|---|---|---|
| [Terms of service](terms-of-service.md) | Organisations that subscribe | Draft |
| [Privacy policy](privacy-policy.md) | People who use UTDRS, and visitors | Draft |
| [Data processing agreement](data-processing-agreement.md) | Organisations, for the personal data in what UTDRS monitors | Draft |
| [Acceptable use policy](acceptable-use-policy.md) | Everyone who uses UTDRS | Draft |
| [Subprocessors](subprocessors.md) | Organisations, as required by the DPA | Draft |

## To fill in

Every `[BRACKETED]` item: your legal entity and its registration, your address, a contact
for privacy and for security, the governing law and courts, prices and payment terms, the
region of your MongoDB Atlas cluster, and the SMTP provider you choose.

## What a lawyer should look at in particular

1. **Which data protection laws apply**, given where you are established and where your
   customers and their people are (for example the EU GDPR, the UK GDPR, or Kenya's Data
   Protection Act 2019), and the transfer mechanism for each country data goes to
   (Render in Frankfurt; MongoDB Atlas in `[ATLAS REGION]`; Vercel; your SMTP provider).
2. **Monitoring employees.** Customers use UTDRS to watch their own people's sign-ins and
   email. Whether, and how, they may do so (notice to staff, works councils, lawful basis)
   is their responsibility under the DPA, but the terms should say so clearly.
3. **Automated response actions** (disabling accounts, removing email) taken by playbooks:
   liability when an action is wrong, and the customer's choice of response mode.
4. **The phishing model's training data** is the Kaggle *Phishing Email Dataset*, licensed
   CC BY-SA 4.0. Whether model weights trained on it are "adapted material" that must be
   shared under the same licence is not settled; get advice before selling UTDRS with it.
5. **Liability caps and warranties** suitable for a security product, where a missed threat
   is the kind of loss customers will claim for.
6. **Security incident notification** times you can meet (the DPA says `[48] hours`).
7. **Erasing a person's account.** UTDRS can deactivate an account but not yet delete one
   (the audit log refers to it). Decide whether that is justified or whether account
   details must be erasable on request (for example replaced by a placeholder, keeping the
   audit log intact); the second needs a feature.
