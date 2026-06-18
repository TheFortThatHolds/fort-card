// chargeCard integration: a spend goes through the card's Durable Object (atomic reserve), then
// injects the key. Proves the spend can't bypass a freeze/revoke and only consumes via the DO.
// The DO logic itself is covered in cardstate.test.mjs; here we test chargeCard's wiring to it.
// Run: node test/charge-freeze.test.mjs
import { chargeCard } from "../src/worker.js";
import { CardState } from "../src/cardstate.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const SPACE = "github:1", ID = "c1", HOST = "api.x.com";
const CARD = { id: ID, name: "t", secret: "k", allowed_hosts: [HOST], header: "Authorization", header_prefix: "Bearer ", limit: 20, used: 5, frozen: false, pending: false };

// env with a real CardState DO (Map-backed) behind CARD_STATE, and a VAULT that serves the secret +
// split-mode last-mile config so the spend relays through callLastMile (a stubbed fetch).
function mkEnv(cardRecord) {
  const m = new Map();
  if (cardRecord) m.set("card", cardRecord);
  const storage = {
    async get(k) { return m.has(k) ? structuredClone(m.get(k)) : undefined; },
    async put(k, v) { m.set(k, structuredClone(v)); },
    async delete(k) { m.delete(k); },
  };
  const inst = new CardState({ storage }, {});
  const stub = { fetch: (url, init) => inst.fetch(new Request(url, init)) };
  const VAULT = {
    async get(key) {
      if (key.endsWith(":secret:k")) return JSON.stringify({ iv: "x", ct: "y" });
      if (key.endsWith(":lastmile:config")) return JSON.stringify({ url: "https://lm.example", key: "relay" });
      return null;
    },
    async put() {}, async delete() {}, async list() { return { keys: [] }; },
  };
  return { CARD_STATE: { idFromName: (n) => n, get: () => stub }, VAULT };
}

let fetched = 0;
globalThis.fetch = async () => { fetched++; return { ok: true, status: 200, async json() { return { status: 200, body: { ok: true } }; }, async text() { return "{}"; } }; };
const req = { url: `https://${HOST}/v` };

(async () => {
  // 1. live card → authorized, the DO counted the spend, upstream called once
  {
    fetched = 0;
    const r = await chargeCard(mkEnv({ ...CARD }), SPACE, ID, req);
    ok(r.authorized === true && r.card.used === 6 && r.card.remaining === 14, "live spend authorized + counted via DO");
    ok(fetched === 1, "upstream called exactly once");
  }

  // 2. frozen → declined, no upstream call (kill-switch holds through chargeCard)
  {
    fetched = 0;
    const r = await chargeCard(mkEnv({ ...CARD, frozen: true }), SPACE, ID, req);
    ok(r.authorized === false && r.decline_reason === "card frozen", "frozen card declined");
    ok(fetched === 0, "frozen card makes no upstream call");
  }

  // 3. revoked (no DO state) → declined "card revoked", not resurrected
  {
    const r = await chargeCard(mkEnv(null), SPACE, ID, req);
    ok(r.authorized === false && r.decline_reason === "card revoked", "missing/revoked card declined");
  }

  // 4. off-host → declined by the DO fence
  {
    const r = await chargeCard(mkEnv({ ...CARD }), SPACE, ID, { url: "https://evil.com/x" });
    ok(r.authorized === false && /not allowed/.test(r.decline_reason), "off-host spend declined");
  }

  // 5. at cap → declined
  {
    const r = await chargeCard(mkEnv({ ...CARD, used: 20 }), SPACE, ID, req);
    ok(r.authorized === false && r.decline_reason === "limit reached", "at cap declined");
  }

  console.log(`\ncharge-freeze: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
