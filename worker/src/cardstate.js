// CardState — a Durable Object: the single, strongly-consistent home for ONE card's LIVE state
// (frozen / pending / revoked / used). One instance per card. Because a DO is single-threaded and
// its storage is transactional, every spend / freeze / revoke for a card SERIALIZES through here:
//   • freeze/revoke take effect instantly and authoritatively (no eventually-consistent KV copies),
//   • a spend is a single atomic "reserve" — fence + increment in one step — so it can NEVER
//     resurrect a revoked card or write a stale frozen:false back over a freeze.
// Only the card's live state lives here; the secret ciphertext stays in KV. This is the kill-switch's
// real foundation — KV (eventually consistent, no atomic compare-and-set) cannot provide it.

// Pure fence: given a card record (or null), an optional host, and an optional req
// {method, path, body}, return a decline reason or null. Exported so the worker and tests
// share ONE definition of "is this spend allowed right now".
//
// allowed_paths / body_match (build-item-38, doc-fort-go-card) are the ENDPOINT-LOCK and
// BODY-CONSTRAINT beyond allowed_hosts: host-lock alone isn't a use-case lock (api.github.com
// is ALL of GitHub). When set, they narrow further — a card with neither behaves exactly as
// before (backward compatible; a lane can only narrow, never widen).
export function fence(c, host, req) {
  if (!c) return "card revoked";
  if (c.pending) return "card pending owner approval";
  if (c.frozen) return "card frozen";
  if (c.expires_at && Date.parse(c.expires_at) < Date.now()) return "card expired";
  if (c.limit != null && (c.used || 0) >= c.limit) return "limit reached";
  if (host != null && (!Array.isArray(c.allowed_hosts) || !c.allowed_hosts.includes(host))) {
    return `host ${host} not allowed for this card`;
  }
  if (Array.isArray(c.allowed_paths) && c.allowed_paths.length) {
    const method = ((req && req.method) || "GET").toUpperCase();
    const p = req && req.path;
    const label = method + " " + (p || "");
    if (!c.allowed_paths.includes(label)) {
      return `endpoint ${label} not allowed for this card`;
    }
  }
  if (c.body_match) {
    let re;
    try { re = new RegExp(c.body_match); } catch { return "card body_match is not a valid pattern"; }
    const b = req && req.body;
    const target = c.body_field ? (b && typeof b === "object" ? b[c.body_field] : undefined) : (typeof b === "string" ? b : JSON.stringify(b));
    if (typeof target !== "string" || !re.test(target)) {
      return "body does not match this card's locked pattern";
    }
  }
  return null;
}

const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json" } });

export class CardState {
  constructor(state, env) { this.state = state; this.env = env; }

  async fetch(request) {
    const op = new URL(request.url).pathname.replace(/^\/+/, "");
    const body = request.method === "POST" ? await request.json().catch(() => ({})) : {};
    const get = () => this.state.storage.get("card");

    // Owner writes the authoritative record (issue / recharge / approve). The ONLY way card state is
    // created or its allowance refilled — never by a spend.
    if (op === "init") { await this.state.storage.put("card", body.card); return J(body.card); }

    if (op === "status") return J((await get()) || null);

    if (op === "freeze") { // freeze=true (any holder) / false = unfreeze+approve (owner-gated upstream)
      const c = await get();
      if (!c) return J({ error: "no such card" }, 404);
      c.frozen = !!body.frozen;
      if (!c.frozen) c.pending = false; // unfreeze of a pending card = approval
      await this.state.storage.put("card", c);
      return J(c);
    }

    if (op === "revoke") { await this.state.storage.delete("card"); return J({ revoked: true }); }

    // THE spend gate: fence + increment, atomically. A revoked card (null) declines and is NOT
    // recreated; a frozen card declines and is NOT un-frozen. The spend can only ever consume.
    if (op === "reserve") {
      const c = await get();
      const reason = fence(c, body.host, { method: body.method, path: body.path, body: body.body });
      if (reason) return J({ authorized: false, decline_reason: reason });
      c.used = (c.used || 0) + 1;
      await this.state.storage.put("card", c);
      return J({ authorized: true, card: c });
    }

    return J({ error: "unknown op " + op }, 404);
  }
}
