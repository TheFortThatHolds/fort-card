// Fort Card — AGENT BEARERS. The human (with a passkey tap) mints a scoped, revocable, TTL'd
// bearer for an agent. The agent then runs autonomously with it — no fingerprint, because the
// human already signed its scope at mint time (DESIGN §4).
//
// What a minted bearer CAN do: use cards within their caps, freeze, revoke — the everyday acts.
// What it CANNOT do: issue an active card, store a secret, rotate, mint another bearer, or reveal
// a raw key. Those stay owner-only and demand a fresh passkey step-up. Worst case from a stolen
// bearer: spend inside caps you already set, until you revoke it. Never escalation, never raw keys.
//
// At rest we store only the SHA-256 HASH of the token — never the token itself. Shown once at mint,
// then unrecoverable (re-mint if lost). Each bearer maps to exactly one space, so presenting it is
// how a non-human caller resolves into its tenant.
//
// Storage:
//   `_bearer:<sha256hex>`        → { space, id, exp }   global lookup (O(1) resolve; TTL'd in KV)
//   `<space>:agent:<id>`         → { id, label, hash, exp, created, revoked }   per-space, for list/revoke

const te = new TextEncoder();
const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function sha256hex(s) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(s)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const bearerKey = (hash) => `_bearer:${hash}`;
const agentKey = (space, id) => `${space}:agent:${id}`;
const agentPrefix = (space) => `${space}:agent:`;

// ── resolve a presented bearer → { space, id } or null. Only `fca_`-prefixed tokens are minted
// bearers; anything else (FORT_KEY / FORT_AGENT_KEY) is handled by the worker's static paths. ──
export async function resolveAgentBearer(env, token) {
  if (!token || !token.startsWith("fca_")) return null;
  const rec = await env.VAULT.get(bearerKey(await sha256hex(token)), "json");
  if (!rec) return null;
  if (rec.exp && Date.now() > rec.exp) return null; // expired (KV TTL usually reaped it already)
  return { space: rec.space, id: rec.id };
}

// ── mint: owner act (the worker gates it behind a passkey step-up). Returns the raw token ONCE. ──
export async function mintAgentBearer(env, space, args) {
  const token = "fca_" + b64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const hash = await sha256hex(token);
  const id = "agt_" + crypto.randomUUID().slice(0, 8);
  const ttlDays = typeof args.ttl_days === "number" && args.ttl_days > 0 ? args.ttl_days : null;
  const exp = ttlDays ? Date.now() + ttlDays * 86400 * 1000 : null;
  const record = { id, label: args.label || "agent", hash, exp, created: new Date().toISOString(), revoked: false };
  await env.VAULT.put(agentKey(space, id), JSON.stringify(record));
  await env.VAULT.put(
    bearerKey(hash),
    JSON.stringify({ space, id, exp }),
    exp ? { expirationTtl: Math.max(60, Math.floor((exp - Date.now()) / 1000)) } : undefined,
  );
  return { id, label: record.label, token, expires_at: exp ? new Date(exp).toISOString() : null };
}

export async function listAgents(env, space) {
  const list = await env.VAULT.list({ prefix: agentPrefix(space), limit: 1000 });
  const out = [];
  for (const k of list.keys) {
    const r = await env.VAULT.get(k.name, "json");
    if (r) out.push({ id: r.id, label: r.label, created: r.created, expires_at: r.exp ? new Date(r.exp).toISOString() : null, revoked: !!r.revoked });
  }
  return out;
}

// ── revoke: drop the global lookup (the bearer stops resolving immediately) and mark the per-space
// record revoked (kept for the audit trail). ──
export async function revokeAgent(env, space, id) {
  const r = await env.VAULT.get(agentKey(space, id), "json");
  if (!r) return { error: "no such agent" };
  await env.VAULT.delete(bearerKey(r.hash));
  r.revoked = true;
  await env.VAULT.put(agentKey(space, id), JSON.stringify(r));
  return { revoked: id };
}
