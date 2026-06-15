// Web Push module: VAPID self-mints (idempotent), subscriptions store/list/remove. Run: node test/push.test.mjs
import { vapidPublicKey, addSubscription, listSubscriptions, removeSubscription } from "../src/push.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

function fakeKV() {
  const m = new Map();
  return {
    async get(k, t) { const v = m.get(k); return v == null ? null : t === "json" ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : String(v)); },
    async delete(k) { m.delete(k); },
    async list({ prefix = "", limit = 100 } = {}) { return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).slice(0, limit).map((name) => ({ name })) }; },
  };
}

(async () => {
  const env = { VAULT: fakeKV() };
  const A = "github:1";

  const pub = await vapidPublicKey(env);
  ok(typeof pub === "string" && pub.length > 80 && !/[+/=]/.test(pub), "VAPID self-mints a base64url public key");
  ok((await vapidPublicKey(env)) === pub, "VAPID mint is idempotent (stable across calls)");

  const sub = { endpoint: "https://push.example.com/abc", keys: { p256dh: "BPexamplekeymaterial", auth: "authsecret16byte" } };
  const { id } = await addSubscription(env, A, sub);
  ok(!!id, "addSubscription returns an id");
  let subs = await listSubscriptions(env, A);
  ok(subs.length === 1 && subs[0].sub.endpoint === sub.endpoint, "subscription is stored + listed");

  // space isolation: another space sees nothing
  ok((await listSubscriptions(env, "github:2")).length === 0, "subscriptions are per-space");

  let threw = false;
  try { await addSubscription(env, A, { endpoint: "x" }); } catch { threw = true; }
  ok(threw, "an invalid subscription (no keys) is rejected");

  await removeSubscription(env, A, sub.endpoint);
  ok((await listSubscriptions(env, A)).length === 0, "removeSubscription deletes it");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
