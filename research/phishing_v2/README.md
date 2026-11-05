# Phishing model v2: do sender and link signals help? (No, on the data we may use)

An experiment, not a model in use. The core engine's phishing model is unchanged.

## Question

The phishing model reads an email's text only. Would adding what UTDRS knows about the
sender and the links (`signals.py`) make the verdict better?

## Data

The Kaggle *Phishing Email Dataset* (Naser Abdullah Alam, **CC BY-SA 4.0**): its files with
sender and link columns, CEAS 2008, SpamAssassin, Nazario and Nigerian Fraud, 49,859 emails
after removing duplicates. Not in this repository: download it from Kaggle (an account is
needed) and give its folder to the script.

Newer data was considered and not used: Phishing Pot (real, current, multilingual phishing
with full headers) is **CC BY-NC 4.0**, non-commercial only, so it cannot train a model for
a commercial product without its maintainer's permission. No openly licensed source of
current, multilingual *legitimate* email exists, which a classifier needs just as much.

## Method

`experiment.py`: one split, 70% to train and 30% held out, stratified by corpus and label.
The same TF-IDF text model (5,000 terms, logistic regression), with and without the six
signals, trained on the same 70% and measured on the same 30%. Nothing that says which
corpus an email came from (recipients, dates) is used.

    python -I experiment.py /path/to/phishing-email-dataset

## Results (held-out 14,958 emails, threshold 0.7)

| | Precision | Recall | Legitimate emails flagged | AUC |
|---|---|---|---|---|
| Text only | 99.69% | 99.19% | 0.40% | 0.9995 |
| Text and signals | 99.67% | 99.12% | 0.44% | 0.9995 |

The signals add nothing; the combined model is marginally worse. What the model learned from
them is about the corpora, not about phishing:

| Signal | Weight | Why |
|---|---|---|
| sender missing | +3.54 | No legitimate email here lacks a sender; some fraud does |
| sender's local part has digits | +1.58 | |
| display name holds a domain | -1.84 | Mailing-list ham ("Name via list.example") |
| free mail sender | -0.90 | 2008 spam rarely came from free mail; today's phishing often does |

Shipping these weights would make the verdict worse on real, current mail.

## What it means

- **This benchmark is saturated.** A plain text model reaches 0.9995 AUC on it; its emails are
  from 2008 and earlier, in English. It cannot measure what matters: newer phishing, other
  languages, and today's senders.
- **Header and link evidence stays in the rules**, which do not depend on this data: failed
  DMARC, risky attachments from outside and replies redirected elsewhere (core engine email
  rules, gateway PR #30), alongside the text model.
- **What would help** is current, labelled, licensed mail, phishing and legitimate:
  permission to use Phishing Pot commercially, or an organisation's own labelled mail
  (reported phishing and a sample of normal mail), used where it is.
