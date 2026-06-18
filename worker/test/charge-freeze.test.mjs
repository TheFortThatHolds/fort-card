// chargeCard kill-switch: a freeze must beat a spend, and a charge must NEVER write a stale
// frozen:false back over a freeze (the lost-update bug that let a card bully through forever).
// Split mode is used so the upstream call goes through callLastMile (a stubbed fetch) — no MASTER_KEY.
// Run: node test/charge-freeze.test.mjs
import { chargeCard, K } from "../src/worker.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const SPACE = "github:1", ID = "card_test", SECRET = "s", HOST = "api.x.com";
const cardKey = K(SPACE, "card", ID), secretKey = K(SPACE, "secret", SECRET), cfgKey = K(SPACE, "lastmile", "config");
const baseCard = (over = {}) => ({ id: ID, name: "t", secret: SECRET, allowed_hosts: [HOST], used: 5, limit: 20, frozen: false, pending: false, ...over });

// env whose card-key reads come from a queue (to simulate state changing mid-charge), recording puts.
function makeEnv(cardReads) {
  const puts = [];
  const env = {
    VAULT: {
      async get(key) {
        if (key === cardKey) return cardReads.length > 1 ? cardReads.shift() : cardReads[0];
        if (key === secretKey) return JSON.stringify({ iv: "x", ct: "y" }); // no keyRef → no DEK fetch
        if (key === cfgKey) return JSON.stringify({ url: "https://lm.example", key: "relay" }); // split mode ON
        return null;
      },
      async put(key, val) { puts.push({ key, val }); },
      async list() { return { keys: [] }; },
    },
  };
  return { env, puts };
}

let fetched = 0;
globalThis.fetch = async () => { fetched++; return { ok: true, status: 200, async json() { return { status: 200, body: { ok: true } }; }, async text() { return "{}"; } }; };
const req = { url: `https://${HOST}/v` };
const cardPuts = (puts) => puts.filter((p) => p.key === cardKey).map((p) => JSON.parse(p.val));

(async () => {
  // 1. already frozen → declined, and we never even make the upstream call
  {
    fetched = 0;
    const { env, puts } = makeEnv([baseCard({ frozen: true })]);
    const r = await chargeCard(env, SPACE, baseCard({ frozen: true }), req);
    ok(r.authorized === false && r.decline_reason === "card frozen", "frozen card is declined");
    ok(fetched === 0, "frozen card makes no upstream call");
    ok(cardPuts(puts).length === 0, "frozen card is never written back (no clobber)");
  }

  // 2. THE BUG: not frozen when the charge starts, frozen by commit time (freeze landed mid-call).
  //    Must decline AND must not write the card at all → the freeze survives.
  {
    fetched = 0;
    const { env, puts } = makeEnv([baseCard({ frozen: false }), baseCard({ frozen: true })]);
    const r = await chargeCard(env, SPACE, baseCard({ frozen: false }), req);
    ok(r.authorized === false && r.decline_reason === "card frozen", "freeze landing mid-charge wins at commit");
    ok(cardPuts(puts).every((c) => c.frozen !== false), "a mid-charge freeze is never overwritten with frozen:false");
    ok(cardPuts(puts).length === 0, "declined-at-commit charge writes no used bump");
  }

  // 3. live + not frozen → authorized, used bumped on the fresh record
  {
    const { env, puts } = makeEnv([baseCard({ frozen: false }), baseCard({ frozen: false })]);
    const r = await chargeCard(env, SPACE, baseCard({ frozen: false }), req);
    ok(r.authorized === true && r.card.used === 6 && r.card.remaining === 14, "live card charges and counts");
    const written = cardPuts(puts).pop();
    ok(written && written.used === 6 && written.frozen === false, "commit writes the fresh record (used=6)");
  }

  // 4. fences read live: a card revoked (gone from KV) mid-flight declines, doesn't recreate it
  {
    const { env, puts } = makeEnv([null]);
    const r = await chargeCard(env, SPACE, baseCard(), req);
    ok(r.authorized === false && r.decline_reason === "card revoked", "revoked (missing) card is declined");
    ok(cardPuts(puts).length === 0, "revoked card is not resurrected by a write");
  }

  // 5. over-cap is enforced on the live read
  {
    const { env } = makeEnv([baseCard({ used: 20, limit: 20 })]);
    const r = await chargeCard(env, SPACE, baseCard({ used: 20, limit: 20 }), req);
    ok(r.authorized === false && r.decline_reason === "limit reached", "limit is enforced on the live read");
  }

  console.log(`\ncharge-freeze: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
