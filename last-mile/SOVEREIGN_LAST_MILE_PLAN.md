# Sovereign last-mile — the build plan

## The requirement (owner-stated, non-negotiable)

A hosted customer's API key **is never visible to the operator — ever.** The customer
runs their **own last-mile worker on their own Cloudflare** (their little vault). The
operator runs the **brain**: the wallet UI, approvals, audit, orchestration — and holds
**only ciphertext**. The operator cannot see a customer's plaintext key at *any* point,
including the moment the customer enters it.

This is the spine of the product, not an upgrade tier. If the operator can ever see the
key, the product has failed its one job.

## What's already true (verified in code)

- **Charge path is non-custodial.** In split mode the control plane sends the last-mile
  only the *sealed* secret + wrapped DEK; the last-mile decrypts + injects + fetches on
  the customer's own box (`worker.js` `callLastMile(.../charge)`; `last-mile/src/worker.js`
  `/charge`). Plaintext stays on the customer's infra. ✅
- **Rotate path is non-custodial.** Control plane ships ciphertext to the last-mile, which
  re-seals; plaintext never leaves the customer's box. ✅
- **Last-mile self-mints its keys** on first boot and exposes `/bootstrap` (first-call-wins
  connect creds), `/seal`, `/charge`, `/rotate`, `/recovery`. ✅

## The two gaps that break the requirement

### Gap 1 — Key entry routes plaintext THROUGH the control plane  *(the security hole)*
`worker.js` `/secrets` store, split mode:
```js
callLastMile(env, "/seal", { plaintext: String(body.value), ... })
```
The control plane receives the **plaintext** and forwards it. Not stored, but the
operator's worker holds it in memory at entry time. **This is the hole the owner flagged.**

**Fix:** the key is sealed at the customer's last-mile **without the control plane ever
seeing plaintext.**
- Recommended: the PWA (in the customer's browser) posts the plaintext **directly to the
  customer's own last-mile origin** `/seal`, gets back `{iv, ct}` ciphertext, and sends
  **only the ciphertext** to the control plane `/secrets` to store. The control plane's
  `/secrets` stops accepting `value` (plaintext) in split mode and accepts `sealed`
  (ciphertext) instead.
- Auth/CORS: the last-mile `/seal` accepts the owner's authenticated call (per-space
  last-mile key held by the browser session, or an owner passkey assertion the last-mile
  verifies). Last-mile already SSRF-guards outbound; `/seal` is inbound-only.
- Alternative considered: asymmetric "encrypt-to-last-mile-pubkey" in the browser so even
  the customer's last-mile only ever sees ciphertext-at-rest. Heavier; revisit later.

### Gap 2 — Last-mile routing is GLOBAL, not per-customer
`worker.js` `splitMode(env)` reads one global `LAST_MILE_URL` / `LAST_MILE_KEY`, so today
the split serves a **single** deployment. Multi-tenant hosted needs each space routed to
**its own** last-mile.

**Fix:**
- Store per-space last-mile creds: `K(space, "lastmile", "config")` → `{ url, key }`
  (the `key` itself sealed at rest, owner-only to set).
- `splitMode(env, space)` and `callLastMile(env, space, ...)` resolve the space's config;
  fall back to global only for self-host/single-tenant.
- **Onboarding:** owner deploys the last-mile (the existing one-tap button installs just
  `last-mile/`), it self-mints + `/bootstrap` returns `{url, key}`, owner registers those
  to their space via a new owner-gated control-plane endpoint
  `POST /lastmile/connect { url, key }` (passkey step-up). From then on their space is
  split-routed to their box, and the control plane drops any ability to decrypt for them.

## Invariants the build must hold

1. The control plane never receives a plaintext key in split mode (entry, charge, or rotate).
2. The audit ledger never stores a key or secret value (already true; keep it true).
3. SSRF fence stays enforced on every last-mile outbound (already true).
4. A customer who hasn't connected a last-mile is **custodial and told so plainly** — or is
   blocked from storing keys until they do (owner decides which; default: tell them plainly).

## Sequence

1. **Gap 1** (non-custodial entry) — the actual hole. Browser → customer last-mile `/seal`
   → store ciphertext. Tests: control plane `/secrets` rejects plaintext in split mode.
2. **Gap 2** (per-space routing + connect flow) — makes it work for many customers.
3. Only after both: the pricing page may say "your key is sealed on your own Cloudflare;
   we hold ciphertext" — because the code earns it.

_Status: planning. Nothing below the line is built yet; this file is the spec._
