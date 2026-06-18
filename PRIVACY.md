# Privacy Policy — TEMPLATE

> **This is a template for the operator of a Fort Card instance to complete and have reviewed by
> counsel before publishing.** Replace every `[BRACKETED]` placeholder. It is not legal advice. It
> describes the data behavior of the Fort Card software as built; your deployment's specifics
> (legal entity, representative, contact) are yours to fill in.

**Service:** Fort Card — a sealed credential wallet. **Operator (controller):** [LEGAL ENTITY, ADDRESS].
**Contact:** [PRIVACY CONTACT EMAIL]. **Last updated:** [DATE].

## Scope
This service is **intended for users in the United States**. It is **not directed at residents of the
EU/EEA or the UK**, and is not marketed there. (An operator who chooses to offer the service to EU/UK
users must additionally complete the EU/UK-specific items below — appoint a representative, confirm
transfer safeguards, etc. Until then those sections do not apply.)

## What we collect
- **Account identity:** your GitHub login/id (via GitHub OAuth) to create and recover your space.
- **Stored secrets:** API keys you choose to store. These are **encrypted** and the wallet **cannot
  read their values** — agents spend them server-side without the plaintext ever being exposed to the
  wallet UI or to us in usable form. We hold only ciphertext plus the **name** you give each secret.
- **Cards & agent bearers:** the configuration you create (names, allowed hosts, limits) — never a
  secret value.
- **Statement / activity log:** an append-only record of actions in your space (card charges,
  approvals, stores, etc.) with timestamps, for your own audit.
- **Billing (if enabled):** processed by Stripe. We store a billing record (subscription id, status,
  period end, the email Stripe reports). We never see or store full card numbers.
- **Passkeys:** public-key credentials for device unlock and per-action step-up. We store public keys
  only — never biometrics, which never leave your device.
- **Push subscriptions (if enabled):** the endpoint your browser provides, to notify you of approvals.

## Why (lawful bases, GDPR Art 6)
- **Performance of a contract:** operating the wallet you signed up for.
- **Legitimate interests:** security, abuse prevention, and the audit log.
- **Consent:** optional emails and push notifications, where applicable.

## Retention & deletion
- Active accounts: data is kept while your space is in use.
- **Lapsed subscriptions:** access locks immediately, but your data is **retained for a 30-day grace
  window**, during which you can re-up, download, or delete it. After the grace window it is
  **permanently deleted**.
- **On demand:** you can export or permanently erase everything at any time, from the wallet or from a
  signed link we email you — your right to erasure does not depend on an active plan.

## Your rights (GDPR Arts 15–22; and equivalents such as CCPA/CPRA)
Access, portability (export), rectification, erasure, restriction, and objection. Exercise them in the
wallet (**Your data & privacy**), via the signed links in our lifecycle emails, or by contacting
[PRIVACY CONTACT EMAIL]. We respond without undue delay (and within any statutory deadline).

## Sub-processors & international transfers
See [`SUBPROCESSORS.md`](./SUBPROCESSORS.md). Data is processed on infrastructure that may be outside
your country; transfers rely on appropriate safeguards (e.g. SCCs / the EU–US Data Privacy Framework).
[CONFIRM YOUR TRANSFER MECHANISM.]

## EU/UK representative (GDPR Art 27)
Not applicable while the service is US-only (see **Scope**). If you later offer it to EU/UK users,
appoint a representative and list [NAME + EU/UK ADDRESS] here.

## Breaches
We maintain a breach-response process and will notify the relevant authority and affected users as
required by law (e.g. GDPR Art 33/34: within 72 hours of awareness where applicable).

## Changes
We will post updates here and, for material changes, notify you.
