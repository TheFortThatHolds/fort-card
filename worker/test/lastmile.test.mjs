// Per-space last-mile resolution: a space's own config wins, the global env is the fallback,
// and one space's last-mile never resolves for another. Run: node test/lastmile.test.mjs
import { K, lastMileConfig, splitMode } from "../src/worker.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

function fakeKV() {
  const m = new Map();
  return {
    async get(k, type) { const v = m.get(k); if (v == null) return null; return type === "json" ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : String(v)); },
    async delete(k) { m.delete(k); },
    async list({ prefix = "", limit = 1000 } = {}) { return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).slice(0, limit).map((name) => ({ name })), list_complete: true }; },
  };
}

(async () => {
  const A = "github:1", B = "github:2";

  // 1. nothing configured anywhere
  {
    const env = { VAULT: fakeKV() };
    ok((await lastMileConfig(env, A)) === null, "no config + no global → null");
    ok((await splitMode(env, A)) === false, "no config → not split (custodial/self-host inline)");
  }

  // 2. global env is the fallback (single-tenant / self-host split)
  {
    const env = { VAULT: fakeKV(), LAST_MILE_URL: "https://g.example.com", LAST_MILE_KEY: "gk" };
    const c = await lastMileConfig(env, A);
    ok(c && c.url === "https://g.example.com" && c.key === "gk", "global env is the fallback");
    ok((await splitMode(env, A)) === true, "global set → split");
  }

  // 3. a space's own config wins over the global
  {
    const env = { VAULT: fakeKV(), LAST_MILE_URL: "https://g.example.com", LAST_MILE_KEY: "gk" };
    await env.VAULT.put(K(A, "lastmile", "config"), JSON.stringify({ url: "https://a.tenant.dev", key: "ak" }));
    const c = await lastMileConfig(env, A);
    ok(c.url === "https://a.tenant.dev" && c.key === "ak", "per-space config overrides the global");
  }

  // 4. isolation: A's last-mile never resolves for B
  {
    const env = { VAULT: fakeKV() };
    await env.VAULT.put(K(A, "lastmile", "config"), JSON.stringify({ url: "https://a.tenant.dev", key: "ak" }));
    ok((await lastMileConfig(env, A)).url === "https://a.tenant.dev", "A resolves to A's last-mile");
    ok((await lastMileConfig(env, B)) === null, "B (no config, no global) → null — spaces don't cross");
  }

  // 5. a malformed config (missing key) is ignored and falls back
  {
    const env = { VAULT: fakeKV(), LAST_MILE_URL: "https://g.example.com", LAST_MILE_KEY: "gk" };
    await env.VAULT.put(K(A, "lastmile", "config"), JSON.stringify({ url: "https://a.tenant.dev" })); // no key
    const c = await lastMileConfig(env, A);
    ok(c.url === "https://g.example.com", "config missing its key is ignored → falls back to global");
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
