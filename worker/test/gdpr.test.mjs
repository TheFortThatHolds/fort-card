// GDPR data-rights integration: buildExport reads card state from the Durable Object (not raw KV),
// never leaks a secret value, and eraseSpace wipes BOTH the KV prefix AND each card's DO state (the
// reconciliation that #19 predated — card live state moved out of KV into CardState). Also a smoke
// check that the lapse sweep no-ops when billing is off.
// Run: node test/gdpr.test.mjs
import { buildExport, eraseSpace, runLifecycle, registerCard, cardOp, K } from "../src/worker.js";
import { CardState } from "../src/cardstate.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const SPACE = "github:1";

// A CardState DO registry: one Map-backed instance per name (space:id), exactly like production.
function mkEnv() {
  const kv = new Map();
  const VAULT = {
    async get(k) { return kv.has(k) ? kv.get(k) : null; },
    async put(k, v) { kv.set(k, typeof v === "string" ? v : String(v)); },
    async delete(k) { kv.delete(k); },
    async list({ prefix = "", cursor } = {}) {
      const keys = [...kv.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name }));
      return { keys, list_complete: true };
    },
    _kv: kv,
  };
  const instances = new Map();
  const instFor = (name) => {
    if (!instances.has(name)) {
      const m = new Map();
      const storage = {
        async get(k) { return m.has(k) ? structuredClone(m.get(k)) : undefined; },
        async put(k, v) { m.set(k, structuredClone(v)); },
        async delete(k) { m.delete(k); },
      };
      instances.set(name, new CardState({ storage }, {}));
    }
    return instances.get(name);
  };
  const CARD_STATE = { idFromName: (n) => n, get: (name) => ({ fetch: (url, init) => instFor(name).fetch(new Request(url, init)) }) };
  return { VAULT, CARD_STATE };
}

(async () => {
  // ── setup: one card (live in its DO + indexed), one stored secret, one event, a billing record ──
  const env = mkEnv();
  const CARD = { id: "c1", name: "CF", secret: "cf-key", allowed_hosts: ["api.cloudflare.com"], header: "Authorization", header_prefix: "Bearer ", limit: 20, used: 3, frozen: false, pending: false };
  await cardOp(env, SPACE, "c1", "init", { card: CARD });
  await registerCard(env, SPACE, "c1");
  await env.VAULT.put(K(SPACE, "secret", "cf-key"), JSON.stringify({ iv: "x", ct: "SECRET_CIPHERTEXT" }));
  await env.VAULT.put(K(SPACE, "event", "2026-06-18T00:00:00Z", "aaaa"), JSON.stringify({ ts: "2026-06-18T00:00:00Z", type: "card.charge" }));
  await env.VAULT.put(K(SPACE, "billing"), JSON.stringify({ status: "active", current_period_end: 9999999999 }));

  // ── buildExport ──
  const exp = await buildExport(env, SPACE);
  ok(exp.cards.length === 1 && exp.cards[0].id === "c1", "export lists the card");
  ok(exp.cards[0].used === 3 && exp.cards[0].allowed_hosts[0] === "api.cloudflare.com", "card state comes from the DO (used + hosts)");
  ok(exp.secret_names.includes("cf-key"), "export lists the secret NAME");
  const blob = JSON.stringify(exp);
  ok(!blob.includes("SECRET_CIPHERTEXT"), "export never includes a secret value/ciphertext");
  ok(exp.events.length === 1, "export includes the statement events");
  ok(/never/i.test(exp.note), "export carries the 'values never included' note");

  // ── eraseSpace: must wipe KV AND the card's DO ──
  const before = await cardOp(env, SPACE, "c1", "status");
  ok(before && before.id === "c1", "card DO is live before erase");
  const deleted = await eraseSpace(env, SPACE, null);
  ok(deleted >= 3, "erase reports KV keys deleted (" + deleted + ")");
  const after = await cardOp(env, SPACE, "c1", "status");
  ok(after === null, "card DO state is gone after erase (no orphaned live card)");
  const leftover = [...env.VAULT._kv.keys()].filter((k) => k.startsWith(SPACE + ":"));
  ok(leftover.length === 0, "no KV keys remain under the space prefix (" + leftover.join(",") + ")");

  // a revoked card can never be charged again — fence returns "card revoked" on null state
  const res = await cardOp(env, SPACE, "c1", "reserve", { host: "api.cloudflare.com" });
  ok(res.authorized === false, "erased card cannot be reserved/charged");

  // ── lapse sweep no-ops with billing off ──
  const life = await runLifecycle({ VAULT: mkEnv().VAULT }); // no STRIPE_KEY
  ok(life.ran === false, "lapse sweep is a no-op when billing is off");

  console.log(`\ngdpr: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})().catch((e) => { console.error(e); process.exit(1); });
