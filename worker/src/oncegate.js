// OnceGate — a Durable Object that consumes a token EXACTLY ONCE, atomically. The reusable fix for
// the same class as the kill-switch: a one-time token (claim code / OAuth code / step-up jti) was
// "consumed" with a KV get-then-delete (or check-then-write), which two near-simultaneous requests
// can race — both read "not used" before either burns it, so the token is honoured twice.
//
// Keyed per token (idFromName(tokenId)): the DO serializes consume() against that token, so the
// FIRST consume wins and every later one is refused — no double-redeem, no replay. A short alarm
// cleans the marker up after the token's max lifetime so nothing accumulates.

export class OnceGate {
  constructor(state, env) { this.state = state; this.env = env; }

  async fetch(request) {
    const ttlSec = Math.min(Math.max(Number(new URL(request.url).searchParams.get("ttl")) || 3600, 60), 86400);
    // Single serialized check-and-burn: if already used, refuse; else mark used + schedule cleanup.
    if (await this.state.storage.get("used")) return Response.json({ ok: false });
    await this.state.storage.put("used", Date.now());
    await this.state.storage.setAlarm(Date.now() + ttlSec * 1000);
    return Response.json({ ok: true });
  }

  async alarm() { await this.state.storage.deleteAll(); } // forget the spent marker after its TTL
}

// Atomically consume a one-time token id. Returns true only the FIRST time for that id.
// `ttlSec` should be >= the token's own max lifetime so the marker outlives any valid replay window.
export async function consumeOnce(env, id, ttlSec = 3600) {
  const stub = env.ONCE_GATE.get(env.ONCE_GATE.idFromName(String(id)));
  const r = await stub.fetch("https://do/consume?ttl=" + ttlSec, { method: "POST" });
  const j = await r.json().catch(() => ({ ok: false }));
  return !!j.ok;
}
