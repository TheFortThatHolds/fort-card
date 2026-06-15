// Agent-bearer lifecycle: mint → resolve → list → revoke → no longer resolves. Run: node test/agents.test.mjs
import { mintAgentBearer, resolveAgentBearer, listAgents, revokeAgent } from "../src/agents.js";

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
  const env = { VAULT: fakeKV() };
  const A = "github:1", B = "github:2";

  const m = await mintAgentBearer(env, A, { label: "ci-bot", ttl_days: 7 });
  ok(m.token.startsWith("fca_"), "mint returns an fca_ bearer");
  ok(!!m.expires_at, "ttl_days sets an expiry");

  const r = await resolveAgentBearer(env, m.token);
  ok(r && r.space === A && r.id === m.id, "the bearer resolves to its space + id");

  ok((await resolveAgentBearer(env, "fca_garbage")) === null, "an unknown bearer resolves to null");
  ok((await resolveAgentBearer(env, "not-an-fca-token")) === null, "a non-fca token is ignored");

  // isolation: a bearer minted in A must never resolve into B's space
  ok((await resolveAgentBearer(env, m.token)).space !== B, "bearer never crosses into another space");

  const list = await listAgents(env, A);
  ok(list.length === 1 && list[0].id === m.id && list[0].label === "ci-bot", "list shows the agent (no token/hash)");
  ok(!("token" in list[0]) && !("hash" in list[0]), "list never leaks the token or hash");

  await revokeAgent(env, A, m.id);
  ok((await resolveAgentBearer(env, m.token)) === null, "a revoked bearer stops resolving immediately");
  ok((await listAgents(env, A))[0].revoked === true, "the audit record is kept, marked revoked");
  ok((await revokeAgent(env, A, "agt_nope")).error, "revoking an unknown agent errors");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
