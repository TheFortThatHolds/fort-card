// Fort Card — BILLING. This module is handed a `charge(request)→{status,body}` and runs every Stripe
// call through it; it never holds or reads the key itself. The operator's Stripe key lives as a
// Cloudflare WORKER SECRET (STRIPE_KEY) — operator infrastructure, encrypted at rest, never in a
// tenant vault, never agent-reachable, never in the repo — and worker.js builds `charge` from it
// (see stripeCharge). Billing only opens Checkout sessions and reads subscription status; it never
// moves money on its own, and it never touches the credential vault.
//
// Config (operator of a managed instance):
//   secret STRIPE_KEY                the operator's Stripe key (billing ON iff set; self-host: leave unset)
//   var    STRIPE_PRICE_ID           (optional) reuse an existing price id instead of auto-creating one
//   var    SUBSCRIPTION_PRICE_CENTS  (optional) monthly price in cents — default 800 ($8) [auto-create only]
//   var    SUBSCRIPTION_CURRENCY     (optional) ISO currency — default "usd"             [auto-create only]
//   var    SUBSCRIPTION_PRODUCT_NAME (optional) product display name — default "Fort Card" [auto-create only]

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

const FORM = { "Content-Type": "application/x-www-form-urlencoded" };
// Run one Stripe API call through `charge`; turn a non-2xx into a thrown error. `charge` carries the
// operator's Stripe key (a Worker secret); this module never holds it.
async function call(charge, req) {
  const r = await charge(req);
  if (r.status >= 400) throw new Error("stripe " + r.status + ": " + ((r.body && r.body.error && r.body.error.message) || r.status));
  return r.body;
}
const post = (charge, path, params) => call(charge, { url: "https://api.stripe.com/v1" + path, method: "POST", headers: FORM, body: formEncode(params) });
const get = (charge, path) => call(charge, { url: "https://api.stripe.com/v1" + path, method: "GET" });

const bkey = (space) => space + ":billing";
async function readBilling(env, space) {
  const raw = await env.VAULT.get(bkey(space));
  return raw ? JSON.parse(raw) : null;
}
async function writeBilling(env, space, rec) {
  await env.VAULT.put(bkey(space), JSON.stringify(rec));
}

// Find-or-create the operator's single subscription product+price by charging the card. Cached in KV
// so it's made once, then reused for every customer. The operator never touches the Stripe dashboard.
export async function ensurePrice(env, charge) {
  // Reuse a pinned/existing price (no auto-create — the narrow billing key needs no Products/Prices
  // write, and the operator keeps ONE price, never a duplicate): STRIPE_PRICE_ID var wins, then KV cache.
  if (env.STRIPE_PRICE_ID) return env.STRIPE_PRICE_ID;
  const cached = await env.VAULT.get("_billing:price");
  if (cached) return cached;
  const product = await post(charge, "/products", {
    name: env.SUBSCRIPTION_PRODUCT_NAME || "Fort Card",
    description: "Fort Card — agent credential wallet (monthly subscription)",
  });
  const price = await post(charge, "/prices", {
    product: product.id,
    unit_amount: priceCents(env),
    currency: env.SUBSCRIPTION_CURRENCY || "usd",
    recurring: { interval: "month" },
  });
  await env.VAULT.put("_billing:price", price.id);
  return price.id;
}

// Open a Checkout session for this space (by charging the card). client_reference_id binds the
// payment back to the space so confirmation can verify the tenant. consent_collection turns on
// Stripe's native ToS agreement on its own page (using the ToS URL set in the operator's Stripe
// settings). Returns the hosted Checkout URL to redirect to.
export async function createCheckout(env, charge, space, origin) {
  const price = await ensurePrice(env, charge);
  const s = await post(charge, "/checkout/sessions", {
    mode: "subscription",
    line_items: [{ price, quantity: 1 }],
    success_url: origin + "/app?billing=success&session_id={CHECKOUT_SESSION_ID}",
    cancel_url: origin + "/app?billing=cancel",
    client_reference_id: space,
    allow_promotion_codes: true,
    consent_collection: { terms_of_service: "required" },
    metadata: { space },
    subscription_data: { metadata: { space } },
  });
  return { url: s.url, id: s.id };
}

// Confirm by QUERYING Stripe (no webhook): the session must be complete, paid, and belong to this
// space. On success we cache the subscription so later checks don't re-charge the card until it expires.
export async function confirmCheckout(env, charge, space, sessionId) {
  const s = await get(charge, "/checkout/sessions/" + encodeURIComponent(sessionId) + "?expand[0]=subscription");
  if (s.client_reference_id !== space) return { subscribed: false, reason: "checkout session does not belong to this space" };
  const paid = s.status === "complete" && (s.payment_status === "paid" || s.payment_status === "no_payment_required");
  if (!paid) return { subscribed: false, reason: "payment not complete (" + s.status + "/" + s.payment_status + ")" };
  const sub = s.subscription && typeof s.subscription === "object" ? s.subscription : null;
  const prev = (await readBilling(env, space)) || {};
  // firstActivation = this space wasn't already active — used to fire the welcome email exactly once
  // (a duplicate confirm call on the same return won't re-send, because prev is active by then).
  const firstActivation = !subActive(prev.status);
  const rec = {
    ...prev,
    customer: s.customer || prev.customer || null,
    // Stripe puts the payer's email on customer_details for a completed Checkout session; keep it so
    // the worker can send the welcome/receipt email without a second Stripe round-trip.
    email: (s.customer_details && s.customer_details.email) || s.customer_email || prev.email || null,
    subscription: sub ? sub.id : s.subscription || prev.subscription || null,
    status: sub ? sub.status : "active",
    current_period_end: sub ? sub.current_period_end : prev.current_period_end || null,
    cancel_at_period_end: sub ? !!sub.cancel_at_period_end : false,
    updated: Date.now(),
  };
  await writeBilling(env, space, rec);
  return { subscribed: true, firstActivation, ...rec };
}

// Is this space subscribed right now? Trust the cached record until its period end, then re-query
// Stripe once (by charging the card) and re-cache. No record → not subscribed. The operator is a
// customer like anyone else — they subscribe through the same Checkout; there's no free pass.
export async function isSubscribed(env, charge, space) {
  const rec = await readBilling(env, space);
  if (!rec) return false;
  if (subActive(rec.status) && rec.current_period_end && Date.now() < rec.current_period_end * 1000) return true;
  if (!rec.subscription) return subActive(rec.status);
  try {
    const sub = await get(charge, "/subscriptions/" + encodeURIComponent(rec.subscription));
    rec.status = sub.status;
    rec.current_period_end = sub.current_period_end;
    rec.cancel_at_period_end = !!sub.cancel_at_period_end; // keep the pending-cancel flag truthful
    rec.updated = Date.now();
    await writeBilling(env, space, rec);
    return subActive(sub.status);
  } catch {
    return subActive(rec.status); // card/Stripe unreachable: fall back to last known status, fail-open for payers
  }
}

// A small read-only summary for /billing/status so the wallet can show "renews <date>" or
// "ends <date>" and the right button. Names/dates only — never a key, never a card value.
export async function billingSummary(env, space) {
  const rec = await readBilling(env, space);
  if (!rec) return { cancel_at_period_end: false, current_period_end: null };
  return { cancel_at_period_end: !!rec.cancel_at_period_end, current_period_end: rec.current_period_end || null };
}

// Cancel — DESIGN: at PERIOD END. The customer keeps full access through the period they
// already paid for, then it lapses. We never cut off mid-period and never prorate a refund — fair,
// boring, and the opposite of a retention maze. It's reversible until the period actually ends
// (resumeSubscription flips it back), so a misclick costs nothing. Stripe escalates the sub to
// `canceled` on its own when the period ends; isSubscribed then naturally returns false.
export async function cancelSubscription(env, charge, space) {
  const rec = await readBilling(env, space);
  if (!rec || !rec.subscription) return { ok: false, reason: "no active subscription" };
  const sub = await post(charge, "/subscriptions/" + encodeURIComponent(rec.subscription), { cancel_at_period_end: true });
  rec.status = sub.status;
  rec.current_period_end = sub.current_period_end;
  rec.cancel_at_period_end = true;
  rec.updated = Date.now();
  await writeBilling(env, space, rec);
  return { ok: true, cancel_at_period_end: true, current_period_end: rec.current_period_end, email: rec.email || null };
}

// Undo a pending cancel (only meaningful while still inside the paid period): flip the flag back off
// so the subscription renews as normal. No charge moves; it's a one-field update on the live sub.
export async function resumeSubscription(env, charge, space) {
  const rec = await readBilling(env, space);
  if (!rec || !rec.subscription) return { ok: false, reason: "no subscription to resume" };
  const sub = await post(charge, "/subscriptions/" + encodeURIComponent(rec.subscription), { cancel_at_period_end: false });
  rec.status = sub.status;
  rec.current_period_end = sub.current_period_end;
  rec.cancel_at_period_end = false;
  rec.updated = Date.now();
  await writeBilling(env, space, rec);
  return { ok: true, cancel_at_period_end: false, current_period_end: rec.current_period_end, email: rec.email || null };
}
