// Billing through a CARD: stripe.js never sees a key — it's handed a `charge(request)` that returns
// {status, body}. We test the pure logic plus the card-mediated flows with a fake charger + an
// in-memory KV. No real Stripe, no key anywhere. Run: node test/stripe.test.mjs
import { priceCents, subActive, formEncode, ensurePrice, createCheckout, confirmCheckout, isSubscribed } from "../src/stripe.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const kv = () => {
  const m = new Map();
  return { get: async (k) => (m.has(k) ? m.get(k) : null), put: async (k, v) => void m.set(k, v), _m: m };
};
// a fake card charger: matches the request URL to a canned {status, body}, records calls.
const charger = (routes) => {
  const calls = [];
  const fn = async (req) => {
    calls.push(req);
    for (const [re, status, body] of routes) if (re.test(req.url)) return { status, body };
    return { status: 404, body: { error: { message: "no route for " + req.url } } };
  };
  fn.calls = calls;
  return fn;
};

// ── pure logic ──
ok(priceCents({}) === 800 && priceCents({ SUBSCRIPTION_PRICE_CENTS: "500" }) === 500, "price defaults to 800, overridable");
ok(priceCents({ SUBSCRIPTION_PRICE_CENTS: "junk" }) === 800, "bad price falls back to 800");
ok(subActive("active") && subActive("trialing") && subActive("past_due") && !subActive("canceled"), "subActive is binary on Stripe status");

const fe = decodeURIComponent(formEncode({ mode: "subscription", line_items: [{ price: "price_1", quantity: 1 }], subscription_data: { metadata: { space: "github:7" } } }));
ok(fe.includes("line_items[0][price]=price_1") && fe.includes("line_items[0][quantity]=1"), "formEncode flattens arrays of objects (Stripe bracket form)");
ok(fe.includes("subscription_data[metadata][space]=github:7"), "formEncode nests values");

// ── ensurePrice: makes product+price by CHARGING the card, caches, reuses ──
{
  const env = { VAULT: kv() };
  const charge = charger([[/\/products$/, 200, { id: "prod_1" }], [/\/prices$/, 200, { id: "price_1" }]]);
  const p1 = await ensurePrice(env, charge);
  const made = charge.calls.length;
  const p2 = await ensurePrice(env, charge);
  ok(p1 === "price_1" && p2 === "price_1", "ensurePrice returns the price id");
  ok(charge.calls.length === made, "ensurePrice is cached (no further charges)");
  ok(charge.calls.every((c) => c.url.startsWith("https://api.stripe.com/")), "every call is a Stripe URL charged through the card");
}

// ── createCheckout: binds the space, turns on Stripe's native ToS consent, returns the url ──
{
  const env = { VAULT: kv() };
  const charge = charger([[/\/products$/, 200, { id: "prod_1" }], [/\/prices$/, 200, { id: "price_1" }], [/\/checkout\/sessions$/, 200, { id: "cs_1", url: "https://checkout.stripe.com/c/cs_1" }]]);
  const out = await createCheckout(env, charge, "github:7", "https://card.example");
  const co = charge.calls.find((c) => /checkout\/sessions/.test(c.url));
  const body = decodeURIComponent(co.body);
  ok(out.url === "https://checkout.stripe.com/c/cs_1", "createCheckout returns the Checkout URL");
  ok(body.includes("client_reference_id=github:7"), "checkout binds the space");
  ok(body.includes("mode=subscription"), "checkout is a subscription");
  ok(body.includes("consent_collection[terms_of_service]=required"), "checkout uses Stripe's native ToS consent");
}

// ── confirmCheckout: only a complete+paid session for THIS space subscribes; caches it ──
{
  const env = { VAULT: kv() };
  let charge = charger([[/\/checkout\/sessions\//, 200, { client_reference_id: "github:7", status: "complete", payment_status: "paid", customer: "cus_1", subscription: { id: "sub_1", status: "active", current_period_end: Math.floor(Date.now() / 1000) + 99999 } }]]);
  const good = await confirmCheckout(env, charge, "github:7", "cs_1");
  ok(good.subscribed && good.subscription === "sub_1", "confirm marks subscribed for a paid session of this space");
  ok((await env.VAULT.get("github:7:billing")) !== null, "confirm caches the billing record");

  charge = charger([[/\/checkout\/sessions\//, 200, { client_reference_id: "github:999", status: "complete", payment_status: "paid" }]]);
  ok(!(await confirmCheckout(env, charge, "github:7", "cs_2")).subscribed, "confirm rejects a session belonging to a different space");

  charge = charger([[/\/checkout\/sessions\//, 200, { client_reference_id: "github:7", status: "open", payment_status: "unpaid" }]]);
  ok(!(await confirmCheckout(env, charge, "github:7", "cs_3")).subscribed, "confirm rejects an unpaid session");
}

// ── isSubscribed: no record → false; cache until period end; re-charge to re-query when expired ──
{
  const env = { VAULT: kv() };
  ok(!(await isSubscribed(env, charger([]), "github:2")), "a space with no record is not subscribed");

  await env.VAULT.put("github:2:billing", JSON.stringify({ subscription: "sub_2", status: "active", current_period_end: Math.floor(Date.now() / 1000) + 99999 }));
  const fresh = charger([[/\/subscriptions\//, 200, { status: "active" }]]);
  ok((await isSubscribed(env, fresh, "github:2")) && fresh.calls.length === 0, "active + within period → no re-query (no card charge)");

  await env.VAULT.put("github:3:billing", JSON.stringify({ subscription: "sub_3", status: "active", current_period_end: Math.floor(Date.now() / 1000) - 10 }));
  const stale = charger([[/\/subscriptions\//, 200, { status: "canceled" }]]);
  ok(!(await isSubscribed(env, stale, "github:3")) && stale.calls.length === 1, "expired cache re-charges the card to re-query and sees the cancellation");
}

// ── a declined/frozen card surfaces as an error, never a silent pass ──
{
  const env = { VAULT: kv() };
  const declines = async () => { throw new Error("Stripe billing card declined: card frozen"); };
  let threw = false;
  try { await createCheckout(env, declines, "github:7", "https://x"); } catch (e) { threw = /declined/.test(e.message); }
  ok(threw, "a frozen/declined billing card stops checkout (freeze = kill switch)");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
