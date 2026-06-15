// Fort Card — BILLING. The worker IS the merchant: it does every Stripe step itself with the
// operator's key (a Worker secret, STRIPE_KEY) — find-or-create the ONE subscription product+price,
// open Checkout sessions, and confirm payment by QUERYING Stripe. No webhook, no hand-built buy
// button, no dashboard scavenger hunt. The operator pastes one key; the worker does the rest.
//
// The customer agrees to the operator's terms via Stripe Checkout's native ToS consent — the
// agreement checkbox lives on Stripe's page, using the ToS URL set in the operator's Stripe settings.
//
// Binary, by design: a space is subscribed or it isn't — no tiers. Gated AT THE DOOR (after
// sign-in, before any wallet use): an unsubscribed space can view its (empty) wallet and subscribe,
// but can't store, issue, charge, or let an agent use it. Self-host leaves STRIPE_KEY unset → billing
// is OFF and nothing is ever gated (the FORT_KEY owner never pays the SaaS operator).
//
// The billing key comes from the wallet's OWN vault by default — the wallet pays for itself out of
// the key it already holds. Set OPERATOR_SPACE to the operator's space and the worker reads the
// Stripe key from that space's vault secret (STRIPE_KEY_SECRET, default "stripe-agent-key"), opening
// it with MASTER_KEY server-side — never a repo secret. A Worker secret STRIPE_KEY still works as a
// fallback for a pure self-host that would rather not put the key in the vault. (Resolution + the
// vault read live in worker.js; this module just receives env.STRIPE_KEY already populated.)
//
// Config (Worker vars/secrets — operator of a managed instance):
//   var    OPERATOR_SPACE          the operator's space (e.g. github:123) whose vault holds the key
//   var    STRIPE_KEY_SECRET       (optional) the vault secret name — default "stripe-agent-key"
//   secret STRIPE_KEY              (optional fallback) the Stripe key as a Worker secret instead
//   var    SUBSCRIPTION_PRICE_CENTS  (optional) monthly price in cents — default 800 ($8)
//   var    SUBSCRIPTION_CURRENCY     (optional) ISO currency — default "usd"
//   var    SUBSCRIPTION_PRODUCT_NAME (optional) the product's display name — default "Fort Card"

export function billingEnabled(env) {
  return !!env.STRIPE_KEY;
}
export function priceCents(env) {
  const n = parseInt(env.SUBSCRIPTION_PRICE_CENTS || "800", 10);
  return Number.isInteger(n) && n > 0 ? n : 800;
}
// A subscription counts as live during a transient payment retry (past_due) too, so a single failed
// charge never instantly locks a paying customer out — Stripe escalates to canceled/unpaid on its own.
export function subActive(status) {
  return status === "active" || status === "trialing" || status === "past_due";
}

// Flatten an object/array into Stripe's bracket form: {a:{b:1},c:[{d:2}]} → a[b]=1&c[0][d]=2.
// Values are percent-encoded; Stripe decodes them server-side (so {CHECKOUT_SESSION_ID} survives).
export function formEncode(obj, prefix) {
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (typeof v === "object") parts.push(formEncode(v, key));
    else parts.push(encodeURIComponent(key) + "=" + encodeURIComponent(String(v)));
  }
  return parts.filter(Boolean).join("&");
}

async function sapi(env, method, path, params) {
  const r = await fetch("https://api.stripe.com/v1" + path, {
    method,
    headers: { Authorization: "Bearer " + env.STRIPE_KEY, "Content-Type": "application/x-www-form-urlencoded" },
    body: params ? formEncode(params) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("stripe " + path + ": " + ((j.error && j.error.message) || r.status));
  return j;
}
async function sget(env, path) {
  const r = await fetch("https://api.stripe.com/v1" + path, { headers: { Authorization: "Bearer " + env.STRIPE_KEY } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("stripe " + path + ": " + ((j.error && j.error.message) || r.status));
  return j;
}

const bkey = (space) => space + ":billing";
async function readBilling(env, space) {
  const raw = await env.VAULT.get(bkey(space));
  return raw ? JSON.parse(raw) : null;
}
async function writeBilling(env, space, rec) {
  await env.VAULT.put(bkey(space), JSON.stringify(rec));
}

// Find-or-create the operator's single subscription product+price. Cached in KV so it's made once,
// then reused for every customer. The operator never touches the Stripe dashboard.
export async function ensurePrice(env) {
  const cached = await env.VAULT.get("_billing:price");
  if (cached) return cached;
  const product = await sapi(env, "POST", "/products", {
    name: env.SUBSCRIPTION_PRODUCT_NAME || "Fort Card",
    description: "Fort Card — agent credential wallet (monthly subscription)",
  });
  const price = await sapi(env, "POST", "/prices", {
    product: product.id,
    unit_amount: priceCents(env),
    currency: env.SUBSCRIPTION_CURRENCY || "usd",
    recurring: { interval: "month" },
  });
  await env.VAULT.put("_billing:price", price.id);
  return price.id;
}

// Open a Checkout session for this space. client_reference_id binds the payment back to the space,
// so confirmation can verify it's the right tenant. Returns the hosted Checkout URL to redirect to.
export async function createCheckout(env, space, origin) {
  const price = await ensurePrice(env);
  const s = await sapi(env, "POST", "/checkout/sessions", {
    mode: "subscription",
    line_items: [{ price, quantity: 1 }],
    success_url: origin + "/app?billing=success&session_id={CHECKOUT_SESSION_ID}",
    cancel_url: origin + "/app?billing=cancel",
    client_reference_id: space,
    allow_promotion_codes: true,
    // Stripe Checkout's native ToS agreement: it renders the "I agree to the Terms of Service"
    // checkbox on Stripe's own page, using the ToS URL configured in the operator's Stripe settings.
    // No app-side checkbox, no ToS link in our code — it's an option on the checkout itself.
    consent_collection: { terms_of_service: "required" },
    metadata: { space },
    subscription_data: { metadata: { space } },
  });
  return { url: s.url, id: s.id };
}

// Confirm by QUERYING Stripe (no webhook): the session must be complete, paid, and belong to this
// space. On success we cache the subscription so later checks don't re-hit Stripe until it expires.
export async function confirmCheckout(env, space, sessionId) {
  const s = await sget(env, "/checkout/sessions/" + encodeURIComponent(sessionId) + "?expand[0]=subscription");
  if (s.client_reference_id !== space) return { subscribed: false, reason: "checkout session does not belong to this space" };
  const paid = s.status === "complete" && (s.payment_status === "paid" || s.payment_status === "no_payment_required");
  if (!paid) return { subscribed: false, reason: "payment not complete (" + s.status + "/" + s.payment_status + ")" };
  const sub = s.subscription && typeof s.subscription === "object" ? s.subscription : null;
  const prev = (await readBilling(env, space)) || {};
  const rec = {
    ...prev,
    customer: s.customer || prev.customer || null,
    subscription: sub ? sub.id : s.subscription || prev.subscription || null,
    status: sub ? sub.status : "active",
    current_period_end: sub ? sub.current_period_end : prev.current_period_end || null,
    updated: Date.now(),
  };
  await writeBilling(env, space, rec);
  return { subscribed: true, ...rec };
}

// Is this space subscribed right now? Trust the cached record until its period end, then re-query
// Stripe once and re-cache. No record → not subscribed. (The operator is a customer like anyone
// else — they subscribe through the same Checkout; there's no free pass.)
export async function isSubscribed(env, space) {
  const rec = await readBilling(env, space);
  if (!rec) return false;
  if (subActive(rec.status) && rec.current_period_end && Date.now() < rec.current_period_end * 1000) return true;
  if (!rec.subscription) return subActive(rec.status);
  try {
    const sub = await sget(env, "/subscriptions/" + encodeURIComponent(rec.subscription));
    rec.status = sub.status;
    rec.current_period_end = sub.current_period_end;
    rec.updated = Date.now();
    await writeBilling(env, space, rec);
    return subActive(sub.status);
  } catch {
    return subActive(rec.status); // Stripe unreachable: fall back to the last known status, fail-open for paying customers
  }
}
