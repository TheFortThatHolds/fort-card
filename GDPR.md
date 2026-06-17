# GDPR / data-protection map

How the Fort Card software supports a compliant deployment, plus the operator-side work that code
can't do. This documents the software's behavior; it is not legal advice.

## What the software does for you (built-in)
- **Data minimization (Art 5(1)(c)):** the wallet never sees raw secret values — they're sealed and
  injected server-side. It stores secret *names*, not values.
- **Security of processing (Art 32):** secrets encrypted at rest; per-action passkey step-up
  (fingerprint/Face ID) for sensitive operations including export and erasure.
- **Access & portability (Arts 15, 20):** `GET /export` and the signed email download link return a
  full JSON export.
- **Erasure (Art 17):** on-demand `POST /erase` (in-app, behind a fresh passkey tap) and a signed
  email delete link wipe the entire space immediately. Not gated on an active subscription.
- **Storage limitation (Art 5(1)(e)):** lapsed accounts are locked, retained for a 30-day grace
  window (with export/delete options), then permanently purged by the scheduled sweep (arm with
  `PURGE_ENABLED`).
- **Records (Art 30):** the per-space append-only statement logs processing actions.

## Operator responsibilities (NOT code — do these)
- [ ] **Publish a privacy policy** (see [`PRIVACY.md`](./PRIVACY.md)) with your lawful bases and
      contact — Arts 12–14.
- [ ] **Appoint an EU/UK representative** (Art 27) if you offer the service to EU/UK users.
- [ ] **Execute sub-processor DPAs** and confirm transfer safeguards — see
      [`SUBPROCESSORS.md`](./SUBPROCESSORS.md).
- [ ] **Designate controller vs processor** roles for your deployment and reflect them in your terms.
- [ ] **Maintain a breach-notification process** (Art 33/34 — 72h to the supervisory authority where
      applicable) plus any local law (e.g. US state breach statutes).
- [ ] **Have counsel review** your terms + privacy policy before publishing.

## Records of processing (Art 30) — starter
| Activity | Purpose | Categories of data | Recipients | Retention |
|---|---|---|---|---|
| Wallet operation | Provide the service | GitHub id; encrypted secrets; card/bearer config; activity log | Cloudflare | Life of account, then 30-day grace + purge |
| Billing | Subscriptions | Billing email; Stripe subscription metadata | Stripe | Per Stripe + your tax-record duties |
| Email | Lifecycle notices | Recipient email; message content | Resend | Transient |

_Complete the bracketed items per deployment; this file describes the software, your legal posture is
yours to finalize._
