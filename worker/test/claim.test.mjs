// Claim codes: one-time, short-TTL, space-bound, stored hashed, resolve code→space, consumed on use.
// Run: node test/claim.test.mjs
import { mintClaimCode, verifyAndConsumeClaim, normalizeClaim, sha256B64 } from "../src/claim.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

function fakeKV() {
  const m = new Map();
  return {
    store: m,
    async get(k) { const v = m.get(k); return v == null ? null : v; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : String(v)); },
    async delete(k) { m.delete(k); },
  };
}

// mock the OnceGate DO binding: consume(id) returns ok:true the first time per id, ok:false after.
function fakeOnce() {
  const used = new Set();
  return {
    idFromName: (n) => n,
    get: (id) => ({ fetch: async () => { const seen = used.has(id); used.add(id); return { json: async () => ({ ok: !seen }) }; } }),
  };
}

(async () => {
  const A = "github:1", B = "github:2";

  // 1. mint → format + verify round-trip
  {
    const env = { VAULT: fakeKV(), ONCE_GATE: fakeOnce() };
    const code = await mintClaimCode(env, A);
    ok(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code), "code is formatted XXXX-XXXX-XXXX-XXXX");
    const res = await verifyAndConsumeClaim(env, code);
    ok(res && res.space === A, "valid code resolves to its space");
  }

  // 2. the raw code is NEVER stored — only its hash
  {
    const env = { VAULT: fakeKV(), ONCE_GATE: fakeOnce() };
    const code = await mintClaimCode(env, A);
    const stored = [...env.VAULT.store.keys()];
    ok(stored.length === 1 && stored[0].startsWith("claim:"), "one global claim: key stored");
    const blob = JSON.stringify([...env.VAULT.store.entries()]);
    ok(!blob.includes(normalizeClaim(code)), "the plaintext code is not present at rest");
    ok(stored[0] === "claim:" + (await sha256B64(normalizeClaim(code))), "key is claim:<sha256(normalized)>");
  }

  // 3. one-time: a second use fails
  {
    const env = { VAULT: fakeKV(), ONCE_GATE: fakeOnce() };
    const code = await mintClaimCode(env, A);
    ok((await verifyAndConsumeClaim(env, code)).space === A, "first use succeeds");
    ok((await verifyAndConsumeClaim(env, code)) === null, "second use fails (consumed)");
    ok(env.VAULT.store.size === 0, "record deleted after consume");
  }

  // 4. forgiving of formatting — lower-case, no dashes, stray spaces all resolve
  {
    const env = { VAULT: fakeKV(), ONCE_GATE: fakeOnce() };
    const code = await mintClaimCode(env, B);
    const messy = " " + code.toLowerCase().replace(/-/g, "") + " ";
    ok((await verifyAndConsumeClaim(env, messy)).space === B, "normalized lookup tolerates case/dashes/spaces");
  }

  // 5. expiry: a code past its TTL is refused (and swept)
  {
    const env = { VAULT: fakeKV(), ONCE_GATE: fakeOnce() };
    const code = await mintClaimCode(env, A, 1); // 1s TTL
    const later = Date.now() + 2000;
    ok((await verifyAndConsumeClaim(env, code, later)) === null, "expired code is refused");
    ok(env.VAULT.store.size === 0, "expired record swept on access");
  }

  // 6. garbage / empty input
  {
    const env = { VAULT: fakeKV(), ONCE_GATE: fakeOnce() };
    ok((await verifyAndConsumeClaim(env, "")) === null, "empty code → null");
    ok((await verifyAndConsumeClaim(env, "NOPE-NOPE-NOPE-NOPE")) === null, "unknown code → null");
    ok((await verifyAndConsumeClaim(env, null)) === null, "null code → null");
  }

  console.log(`\nclaim: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
