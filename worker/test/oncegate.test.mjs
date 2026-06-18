// OnceGate: a token is consumable EXACTLY once — the first consume wins, every later one is refused.
// This is the atomic fix for the one-time-code race (claim / oauth / step-up). Run: node test/oncegate.test.mjs
import { OnceGate, consumeOnce } from "../src/oncegate.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

// mock DO: Map-backed storage + a captured alarm time
function mkInstance() {
  const m = new Map();
  let alarm = null;
  const storage = {
    async get(k) { return m.get(k); },
    async put(k, v) { m.set(k, v); },
    async deleteAll() { m.clear(); },
    async setAlarm(t) { alarm = t; },
  };
  const inst = new OnceGate({ storage }, {});
  return { inst, m, getAlarm: () => alarm };
}

// build an env whose ONCE_GATE routes idFromName(id) → a per-id OnceGate instance (like the runtime)
function mkEnv() {
  const byId = new Map();
  return {
    ONCE_GATE: {
      idFromName: (n) => n,
      get: (id) => {
        if (!byId.has(id)) byId.set(id, mkInstance().inst);
        const inst = byId.get(id);
        return { fetch: (url, init) => inst.fetch(new Request(url, init)) };
      },
    },
  };
}

(async () => {
  // direct DO: first consume ok, second refused, mark + alarm set
  {
    const { inst, m, getAlarm } = mkInstance();
    const r1 = await (await inst.fetch(new Request("https://do/consume?ttl=600", { method: "POST" }))).json();
    const r2 = await (await inst.fetch(new Request("https://do/consume?ttl=600", { method: "POST" }))).json();
    ok(r1.ok === true, "first consume succeeds");
    ok(r2.ok === false, "second consume is refused");
    ok(m.get("used") != null, "the spent marker is stored");
    ok(getAlarm() != null, "a cleanup alarm is scheduled");
  }

  // alarm clears the marker (so the id can be reused after its TTL — storage doesn't accumulate)
  {
    const { inst, m } = mkInstance();
    await inst.fetch(new Request("https://do/consume", { method: "POST" }));
    await inst.alarm();
    ok(m.get("used") == null, "alarm forgets the spent marker");
  }

  // helper: consumeOnce(env,id) — true once per id, false after; different ids independent
  {
    const env = mkEnv();
    ok((await consumeOnce(env, "tokenA")) === true, "consumeOnce(A) first → true");
    ok((await consumeOnce(env, "tokenA")) === false, "consumeOnce(A) again → false");
    ok((await consumeOnce(env, "tokenB")) === true, "consumeOnce(B) independent → true");
  }

  console.log(`\noncegate: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
