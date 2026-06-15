// Billing: the worker is the merchant. We test the pure logic (form-encoding, status reading,
// price/tos resolution) and the network paths (ensure/checkout/confirm/isSubscribed) against a
// stubbed global fetch + an in-memory KV. No real Stripe. Run: node test/stripe.test.mjs
import {
  billingEnabled, priceCents, subActive, formEncode,
  ensurePrice, createCheckout, confirmCheckout, isSubscribed,
} from "../src/stripe.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

// in-memory KV
const kv = () => {
  const m = new Map();
  return { get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => void m.set(k, v), _m: m };
};

// ── pure logic ──
ok(billingEnabled({ STRIPE_KEY: "sk_test" }) && !billingEnabled({}), "billing on iff STRIPE_KEY set");
ok(priceCents({}) === 800 && priceCents({ SUBSCRIPTION_PRICE_CENTS: "500" }) === 500, "price defaults to 800, overridable");
ok(priceCents({ SUBSCRIPTION_PRICE_CENTS: "junk" }) === 800, "bad price falls back to 800");
ok(subActive("active") && subActive("trialing") && subActive("past_due") && !subActive("canceled"), "subActive is binary on Stripe status");

const fe = formEncode({ mode: "subscription", line_items: [{ price: "price_1", quantity: 1 }], subscription_data: { metadata: { space: "github:7" } } });
const feDec = decodeURIComponent(fe);
ok(feDec.includes("line_items[0][price]=price_1") && feDec.includes("line_items[0][quantity]=1"), "formEncode flattens arrays of objects (Stripe bracket form, percent-encoded)");
ok(feDec.includes("subscription_data[metadata][space]=github:7") && fe.includes("github%3A7"), "formEncode nests + percent-encodes (Stripe decodes server-side)");

// ── network paths against a stub ──
let calls = [];
const stub = (routes) => async (urlStr, opts) => {
  calls.push({ url: urlStr, method: (opts && opts.method) || "GET", body: opts && opts.body });
  for (const [re, payload] of routes) if (re.test(urlStr)) return { ok: true, json: async () => payload };
  return { ok: false, json: async () => ({ error: { message: "no stub for " + urlStr } }) };
};
const realFetch = globalThis.fetch;

// ensurePrice: creates product+price once, caches the price id, reuses it next time
{
  calls = [];
  globalThis.fetch = stub([
    [/\/v1\/products$/, { id: "prod_1" }],
    [/\/v1\/prices$/, { id: "price_1" }],
  ]);
  const env = { STRIPE_KEY: "sk", VAULT: kv() };
  const p1 = await ensurePrice(env);
  const made = calls.length;
  const p2 = await ensurePrice(env);
  ok(p1 === "price_1" && p2 === "price_1", "ensurePrice returns the price id");
  ok(calls.length === made, "ensurePrice is cached (no Stripe calls the second time)");
}

// createCheckout: binds the space via client_reference_id, returns the hosted url
{
  calls = [];
  globalThis.fetch = stub([
    [/\/v1\/products$/, { id: "prod_1" }],
    [/\/v1\/prices$/, { id: "price_1" }],
    [/\/v1\/checkout\/sessions$/, { id: "cs_1", url: "https://checkout.stripe.com/c/cs_1" }],
  ]);
  const env = { STRIPE_KEY: "sk", VAULT: kv() };
  const out = await createCheckout(env, "github:7", "https://card.example");
  const co = calls.find((c) => /checkout\/sessions/.test(c.url));
  ok(out.url === "https://checkout.stripe.com/c/cs_1", "createCheckout returns the Checkout URL");
  ok(co.body.includes("client_reference_id=github%3A7"), "checkout binds the space (client_reference_id)");
  ok(co.body.includes("mode=subscription"), "checkout is a subscription");
  ok(decodeURIComponent(co.body).includes("consent_collection[terms_of_service]=required"), "checkout uses Stripe's native ToS consent");
}

// confirmCheckout: only a complete+paid session for THIS space subscribes; caches the subscription
{
  const env = { STRIPE_KEY: "sk", VAULT: kv() };
  globalThis.fetch = stub([[/\/checkout\/sessions\//, { client_reference_id: "github:7", status: "complete", payment_status: "paid", customer: "cus_1", subscription: { id: "sub_1", status: "active", current_period_end: Math.floor(Date.now() / 1000) + 99999 } }]]);
  const good = await confirmCheckout(env, "github:7", "cs_1");
  ok(good.subscribed && good.subscription === "sub_1", "confirm marks subscribed for a paid session of this space");
  ok((await env.VAULT.get("github:7:billing")) !== null, "confirm caches the billing record");

  globalThis.fetch = stub([[/\/checkout\/sessions\//, { client_reference_id: "github:999", status: "complete", payment_status: "paid" }]]);
  const wrong = await confirmCheckout(env, "github:7", "cs_2");
  ok(!wrong.subscribed, "confirm rejects a session belonging to a different space");

  globalThis.fetch = stub([[/\/checkout\/sessions\//, { client_reference_id: "github:7", status: "open", payment_status: "unpaid" }]]);
  const unpaid = await confirmCheckout(env, "github:7", "cs_3");
  ok(!unpaid.subscribed, "confirm rejects an unpaid session");
}

// isSubscribed: no free pass; cache-until-period-end; re-query when expired
{
  const env = { STRIPE_KEY: "sk", VAULT: kv() };
  ok(!(await isSubscribed(env, "github:2")), "a space with no record is not subscribed");

  await env.VAULT.put("github:2:billing", JSON.stringify({ subscription: "sub_2", status: "active", current_period_end: Math.floor(Date.now() / 1000) + 99999 }));
  let hits = 0;
  globalThis.fetch = async () => { hits++; return { ok: true, json: async () => ({ status: "active" }) }; };
  ok((await isSubscribed(env, "github:2")) && hits === 0, "active + within period → no Stripe re-query");

  await env.VAULT.put("github:3:billing", JSON.stringify({ subscription: "sub_3", status: "active", current_period_end: Math.floor(Date.now() / 1000) - 10 }));
  globalThis.fetch = stub([[/\/subscriptions\//, { status: "canceled" }]]);
  ok(!(await isSubscribed(env, "github:3")), "expired cache re-queries Stripe and sees the cancellation");
}

globalThis.fetch = realFetch;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
