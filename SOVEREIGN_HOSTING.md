# Sovereign Hosting — the split model (so the operator never holds a customer's key)

**Goal:** a hosted ($8/mo) customer signs up, but **the operator (Fort Card) cannot read their
API keys.** The way to do that is the **split deploy**: the operator runs the *control plane*
(holds only ciphertext); each customer runs their own *last-mile* worker on their **own
Cloudflare** (holds the `MASTER_KEY`, does the decrypt+inject on their box).

This is already in the code (`splitMode()` in `worker/src/worker.js`, and `last-mile/`). This doc
is the deploy/onboarding shape + the honest security analysis of what's done and what's still a
decision.

---

## What's done (this branch)

- **The last-mile is its own self-contained folder** → `last-mile/` (its own `wrangler.toml`,
  `main = src/worker.js`). That makes it **one-tap deployable on its own**, without dragging the
  whole repo along:
  ```
  https://deploy.workers.cloudflare.com/?url=https://github.com/TheFortThatHolds/fort-card/tree/main/last-mile
  ```
  Cloudflare treats that subfolder as the project root and deploys **only** the last-mile. The KV
  namespace auto-provisions; the worker **self-mints** its own `MASTER_KEY` + `LAST_MILE_KEY` on
  first boot — the customer types no keys.
- **Security hardening (this branch):**
  - SSRF guard now also blocks integer-encoded (`2130706433`), hex (`0x7f000001`), octal
    (`0177.0.0.1`), and IPv4-mapped-IPv6 (`::ffff:127.0.0.1`) loopback/private targets, plus
    malformed octets. Tested in `worker/test/ssrf.test.mjs` (30 cases pass).
  - Last-mile bearer check is now **constant-time** (`safeEqual`), so the token can't be recovered
    by response-timing.

## Cloudflare cost for the customer

As of now, the last-mile fits inside Cloudflare's **free** Workers tier (it's read-mostly: reads
its own key, decrypts, fetches, returns — no per-charge KV writes). Cloudflare sets and can change
those limits — see their current [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).
High-volume/commercial use may fall into their paid plan. (No absolute promises about a third
party's pricing — per Fort doctrine.)

---

## Onboarding — the realistic options

**The "Deploy to Cloudflare" button has no callback/redirect** (verified: the only URL param is
`url`; the user lands on a Cloudflare success page we don't control). So the button can't auto-flow
back into our app. Two honest paths:

### v1 — button + one paste (ships now, no new Cloudflare features)
1. Customer signs into the hosted wallet → their space is born.
2. Wizard **gates** them: "deploy your key-holder first" → the one-tap button (new tab).
3. They deploy; the last-mile self-mints keys and exposes `/bootstrap` (first-call-wins).
4. Customer pastes **one thing back** — their new worker's URL. The control plane calls that
   worker's `/bootstrap` itself, claims the connect key, stores it for their space, and drops its
   own `MASTER_KEY`. Linked.

It's **not** literally one tap (the paste is real), but it's honest and ships with zero dependency
on anything new.

### v2 — true tap-and-done (Cloudflare OAuth, shipped 2026-06-03)
Cloudflare now has **self-managed OAuth clients**: the customer clicks "Connect Cloudflare" and
consents **once**, and our backend provisions the last-mile **into their own account** via the
Cloudflare API and reads the URL back automatically — no paste. The worker still lives on the
**customer's** account/billing (key stays on their infra). Cost: a real build (OAuth handshake +
Worker-upload/KV API calls + domain verification + making the OAuth app public), and the feature is
~2 weeks old (thin docs, may shift). Source:
[Cloudflare self-managed OAuth clients](https://developers.cloudflare.com/changelog/post/2026-06-03-public-oauth-clients/).
**Not** Workers-for-Platforms — that runs customer code under *our* account, which defeats the goal.

---

## ⚠️ The real decisions still open (NOT auto-built — these are trust/architecture calls)

These weren't implemented autonomously because they're genuine design choices with product
tradeoffs, and a *false* sense of sovereignty is the worst outcome for this product.

### 1. Multi-tenant routing: `splitMode` is currently GLOBAL
`splitMode(env)` reads one global `LAST_MILE_URL`/`LAST_MILE_KEY`. That's correct for **single-tenant
self-host split** (one person, one control plane, one last-mile). It is **not** enough for the
hosted multi-tenant model, where **each space needs its own last-mile**. To ship hosted-sovereign,
the control plane must store last-mile `{url, key}` **per space** and route each space's
charge/seal/rotate to that space's worker.

### 2. The autonomous-use vs host-blind tradeoff (the core tension)
**Autonomous server-side charging** (an agent spends a card while the customer is away) **requires**
the control plane to hold a credential it can present to the customer's last-mile. Anything the
operator's server can present, the operator can also present. So:
- **Host-blind** (operator literally cannot use the key) ⟹ charges need the customer present
  (passkey/PRF) ⟹ no autonomous use.
- **Autonomous** ⟹ the operator's server holds a usable token ⟹ the operator *could* drive charges.

You can't have both for the same secret. The clean answer is the **two-tier** model already noted in
the 2026-06-14 design (autonomous/custodial vs sovereign/PRF-sealed), surfaced per secret.

### 3. Scope the last-mile bearer so the operator can't *exfiltrate* the raw key
Today one `LAST_MILE_KEY` gates `/charge`, `/seal`, `/rotate` **and `/recovery`**. If the hosted
control plane ever holds that token (to charge autonomously), whoever runs the control plane could
call `/recovery` and walk away with the customer's `MASTER_KEY`. **Recommendation:** split it into a
**charge-only token** (handed to the control plane) and a **recovery/admin token** (kept by the
customer only). Then even in autonomous mode the operator gets **card-mediated use** (bounded,
logged, freezable) but **never the raw key** — "cards, not keys," applied to the operator too.
(Not a live bug today: hosted multi-tenant routing isn't wired yet, so in the current single-tenant
split the operator *is* the customer.)

---

## Recommendation

Ship **v1** (one-tap last-mile deploy + one paste to link) as the honest first cut, implement
**per-space routing (#1)** and the **two-token scope (#3)** to make hosted-sovereign real, decide the
**autonomous/host-blind tier (#2)** as product policy, and treat **v2 OAuth tap-and-done** as the
polish once the model is proven.
