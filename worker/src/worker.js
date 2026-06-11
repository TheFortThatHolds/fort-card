// Fort Card — a self-hostable credential card-network for the agent era.
//
// Issue API credentials like CREDIT CARDS, not keys: scoped, capped, freezable pointers at
// secrets that live encrypted in your vault. When a card is "charged," the real key is
// injected server-side and the upstream response is returned — the caller NEVER sees the
// key. Steal a card → it's locked to one host, capped, and freezable. Steal a key → game over.
//
// One file, no dependencies, runs on Cloudflare Workers. Fork it, read it, run your own.
//
// HTTP API (all routes require  Authorization: Bearer <FORT_KEY>):
//   POST   /secrets            {name, value}                       store a secret (encrypted at rest)
//   POST   /cards              {name, secret, allowed_hosts, ...}  issue a card
//   GET    /cards                                                  list cards (never the key)
//   POST   /cards/:id/use      {url, method?, headers?, body?}     charge: authorize + settle
//   POST   /cards/:id/freeze   {frozen}                            freeze / unfreeze (kill switch)
//   DELETE /cards/:id                                              revoke
//
// Bindings (see wrangler.toml):
//   KV namespace `VAULT`
//   secret `FORT_KEY`    admin bearer token you choose
//   secret `MASTER_KEY`  base64 of 32 random bytes:  openssl rand -base64 32

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });

async function masterKey(env) {
  return crypto.subtle.importKey("raw", b64d(env.MASTER_KEY), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encrypt(env, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await masterKey(env), enc.encode(plaintext));
  return { iv: b64e(iv.buffer), ct: b64e(ct) };
}
async function decrypt(env, s) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(s.iv) }, await masterKey(env), b64d(s.ct));
  return dec.decode(pt);
}

export default {
  async fetch(request, env) {
    if (!env.MASTER_KEY || !env.FORT_KEY) {
      return json({ error: "server not configured — set FORT_KEY and MASTER_KEY secrets" }, 500);
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/" ) return json({ name: "fort-card", ok: true, docs: "https://github.com/TheFortThatHolds/fort-card" });

    // Every route is admin-gated by a bearer token you set.
    if ((request.headers.get("Authorization") || "") !== "Bearer " + env.FORT_KEY) {
      return json({ error: "unauthorized" }, 401);
    }
    const body = request.method === "GET" ? {} : await request.json().catch(() => ({}));

    // ── store a secret (encrypted; the value never comes back out) ──
    if (path === "/secrets" && request.method === "POST") {
      if (!body.name || !body.value) return json({ error: "name and value required" }, 400);
      await env.VAULT.put("secret:" + body.name, JSON.stringify(await encrypt(env, String(body.value))));
      return json({ ok: true, name: body.name });
    }

    // ── issue a card (a limited, host-locked pointer at a secret) ──
    if (path === "/cards" && request.method === "POST") {
      if (!body.name || !body.secret || !Array.isArray(body.allowed_hosts) || body.allowed_hosts.length === 0) {
        return json({ error: "name, secret, and a non-empty allowed_hosts array are required" }, 400);
      }
      const id = "card_" + crypto.randomUUID().slice(0, 8);
      const card = {
        id,
        name: body.name,
        secret: body.secret,
        allowed_hosts: body.allowed_hosts.map(String),
        header: body.header || "Authorization",
        header_prefix: body.header_prefix ?? "Bearer ",
        limit: typeof body.limit === "number" ? body.limit : null,
        used: 0,
        expires_at: body.expires_at || null,
        frozen: false,
        created: new Date().toISOString(),
      };
      await env.VAULT.put("card:" + id, JSON.stringify(card));
      return json(card);
    }

    // ── list cards (the statement — never the underlying key) ──
    if (path === "/cards" && request.method === "GET") {
      const list = await env.VAULT.list({ prefix: "card:" });
      const cards = [];
      for (const k of list.keys) {
        const c = JSON.parse(await env.VAULT.get(k.name));
        cards.push({
          id: c.id, name: c.name, secret: c.secret, allowed_hosts: c.allowed_hosts,
          limit: c.limit, used: c.used, remaining: c.limit != null ? Math.max(0, c.limit - c.used) : null,
          expires_at: c.expires_at, frozen: c.frozen,
        });
      }
      return json({ cards });
    }

    // ── /cards/:id  (use · freeze · revoke) ──
    const m = path.match(/^\/cards\/([^/]+)(\/use|\/freeze)?$/);
    if (m) {
      const id = m[1];
      const sub = m[2];
      const raw = await env.VAULT.get("card:" + id);
      if (!raw) return json({ error: "no such card" }, 404);
      const card = JSON.parse(raw);

      if (sub === "/freeze" && request.method === "POST") {
        card.frozen = !!body.frozen;
        await env.VAULT.put("card:" + id, JSON.stringify(card));
        return json({ id, frozen: card.frozen });
      }
      if (!sub && request.method === "DELETE") {
        await env.VAULT.delete("card:" + id);
        return json({ revoked: id });
      }
      if (sub === "/use" && request.method === "POST") {
        // authorize (ISO-8583 in spirit)
        if (card.frozen) return json({ authorized: false, decline: "card frozen" });
        if (card.expires_at && Date.parse(card.expires_at) < Date.now()) return json({ authorized: false, decline: "card expired" });
        if (card.limit != null && card.used >= card.limit) return json({ authorized: false, decline: "limit reached" });
        if (!body.url) return json({ authorized: false, decline: "request url required" });
        let host;
        try { host = new URL(body.url).host; } catch { return json({ authorized: false, decline: "bad url" }); }
        if (!card.allowed_hosts.includes(host)) return json({ authorized: false, decline: `host ${host} not allowed for this card` });

        // settle: the vault injects the real key server-side and returns ONLY the response
        const secRaw = await env.VAULT.get("secret:" + card.secret);
        if (!secRaw) return json({ authorized: false, decline: "secret missing from vault" });
        const key = await decrypt(env, JSON.parse(secRaw));
        const resp = await fetch(body.url, {
          method: body.method || "GET",
          headers: { [card.header]: card.header_prefix + key, ...(body.headers || {}) },
          body: body.body == null ? undefined : typeof body.body === "string" ? body.body : JSON.stringify(body.body),
        });
        const text = await resp.text();
        let out;
        try { out = JSON.parse(text); } catch { out = text; }
        card.used++;
        await env.VAULT.put("card:" + id, JSON.stringify(card));
        return json({
          authorized: true,
          status: resp.status,
          body: out,
          card: { id, used: card.used, remaining: card.limit != null ? Math.max(0, card.limit - card.used) : null },
        });
      }
    }

    return json({ error: "not found" }, 404);
  },
};
