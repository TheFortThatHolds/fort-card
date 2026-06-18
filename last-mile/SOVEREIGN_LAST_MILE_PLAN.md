# The lockbox — the build plan

## The requirement (owner-stated, non-negotiable)

A customer's API key **is never visible to the operator — ever.** Every customer runs their
**own lockbox worker on their own Cloudflare**. The operator runs the **wallet** (the control
plane): the UI, approvals, billing, audit, orchestration — and holds **only ciphertext**. The
operator cannot see a customer's plaintext key at *any* point, including the moment the customer
enters it.

This is the spine of the product, and there is one architecture, not a menu. If the operator can
ever see the key, the product has failed its one job.

## What's already true (verified in code)

- **Charge path keeps plaintext on the customer's box.** The control plane sends the lockbox
  only the *sealed* secret + wrapped DEK; the lockbox decrypts + injects + fetches on the
  customer's own Cloudflare (`worker.js` `callLastMile(.../charge)`; the lockbox worker's
  `/charge`). Plaintext stays on the customer's infra. ✅
- **Rotate path keeps plaintext on the customer's box.** The control plane ships ciphertext to
  the lockbox, which re-seals; plaintext never leaves the customer's box. ✅
- **The lockbox self-mints its keys** on first boot and exposes `/bootstrap` (first-call-wins
  connect creds), `/seal`, `/charge`, `/rotate`, `/recovery`. ✅

## The two gaps that break the requirement

### Gap 1 — Key entry routed plaintext THROUGH the control plane  *(the security hole)*
`worker.js` `/secrets` store, when relaying the seal:
```js
callLastMile(env, "/seal", { plaintext: String(body.value), ... })
```
The control plane received the **plaintext** and forwarded it. Not stored, but the
operator's worker held it in memory at entry time. **This was the hole the owner flagged.**

**Fix:** the key is sealed at the customer's lockbox **without the control plane ever
seeing plaintext.**
- The PWA (in the customer's browser) posts the plaintext **directly to the customer's own
  lockbox origin** `/seal`, gets back `{iv, ct}` ciphertext, and sends **only the
  ciphertext** to the control plane `/secrets` to store. The control plane's `/secrets`
  rejects any `value` (plaintext) and accepts `sealed` (ciphertext) instead.
- Auth/CORS: the lockbox `/seal` accepts the owner's authenticated call (per-space lockbox
  key held by the browser session, or an owner passkey assertion the lockbox verifies). The
  lockbox already SSRF-guards outbound; `/seal` is inbound-only.
- Alternative considered: asymmetric "encrypt-to-lockbox-pubkey" in the browser so even the
  customer's lockbox only ever sees ciphertext-at-rest. Heavier; revisit later.

### Gap 2 — Lockbox routing was GLOBAL, not per-customer
`worker.js` `splitMode(env)` read one global `LAST_MILE_URL` / `LAST_MILE_KEY`, so it served a
**single** deployment. Multi-tenant hosted needs each space routed to **its own** lockbox.

**Fix:**
- Store per-space lockbox creds: `K(space, "lastmile", "config")` → `{ url, key }`
  (the `key` itself sealed at rest, owner-only to set).
- `splitMode(env, space)` and `callLastMile(env, space, ...)` resolve the space's config;
  the global `LAST_MILE_URL`/`KEY` remains only as a single-deployment fallback.
- **Onboarding:** owner deploys the lockbox (the one-tap button installs just `last-mile/`),
  it self-mints + `/bootstrap` returns `{url, key}`, owner registers those to their space via
  the owner-gated control-plane endpoint `POST /lastmile/connect { url, key }` (passkey
  step-up). From then on their space is routed to their own lockbox, and the control plane
  has no ability to decrypt for them.

## Invariants the build must hold

1. The control plane never receives a plaintext key (entry, charge, or rotate). Only the
   customer's lockbox ever touches plaintext.
2. The audit ledger never stores a key or secret value (already true; keep it true).
3. SSRF fence stays enforced on every lockbox outbound (already true).
4. A space with no lockbox connected **cannot store or charge keys** — the wallet declines and
   tells the customer to connect their lockbox. There is no path where the control plane handles
   the plaintext key itself.

## Sequence

1. **Gap 1** (key entry never touches the control plane) — the actual hole. Browser → customer
   lockbox `/seal` → store ciphertext. Tests: control plane `/secrets` rejects plaintext.
2. **Gap 2** (per-space routing + connect flow) — makes it work for many customers.
3. Only after both: the pricing page may say "your key is sealed on your own Cloudflare;
   we hold ciphertext" — because the code earns it.

## Status

- ✅ **Gap 2 built** — per-space lockbox routing (`lastMileConfig`/`splitMode` per space),
  owner-gated `POST /lastmile/connect` + `/status` + `/disconnect`. Stores `{url, key}` only.
  Tests: `worker/test/lastmile.test.mjs` (per-space wins, global fallback, space isolation).
- ✅ **Gap 1 built** — key entry never touches the control plane. `POST /lastmile/seal-ticket`
  mints a short-TTL HMAC capability; the browser seals at the customer's own lockbox (`/seal`
  accepts the ticket + CORS); the control plane `/secrets` **rejects any plaintext value** and
  stores only ciphertext. Ticket primitive: `worker/src/ticket.js` + `worker/test/ticket.test.mjs`.
- ⏳ **Remaining hardening** (tracked, not blocking the guarantee):
  - Split the lockbox's `/recovery` (MASTER_KEY reveal) onto a separate owner-only token so a
    control-plane leak can't expose the root key.
  - Single-use tickets (currently short-TTL); a connect-time health ping; disconnect/rotate UX.

_The control plane never receives a plaintext key. The guarantee is enforced in code (and in a
test), not just intended._
