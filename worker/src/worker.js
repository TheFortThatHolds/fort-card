// Fort Card — a self-hostable credential card-network for the agent era.
//
// Issue API credentials like CREDIT CARDS, not keys: scoped, capped, freezable pointers at
// secrets that live encrypted in your vault. When a card is "charged," the real key is
// injected server-side and the upstream response is returned — the caller NEVER sees the
// key. Steal a card → it's locked to one host, capped, and freezable. Steal a key → game over.
//
// MULTI-TENANT. Every record is walled behind a SPACE prefix, so one deployment can host many
// tenants — each sealed in its own space with its own secrets, cards, statement, AND its own
// data key. Today the space is resolved from the owner/agent token (a single space,
// `FORT_SPACE`, default "owner"); OAuth sign-in (GitHub / Google) maps each verified identity
// to its own space, so strangers self-onboard and never see across. Self-host stays single-
// tenant for free — you just never add a second space.
//
// HUMAN-IN-THE-LOOP. A per-card limit means nothing if the holder can mint a fresh card or
// refill its own allowance — so ISSUING and RE-AUTHORIZING (unfreezing) a card are OWNER acts.
// This worker tells human from agent by WHICH TOKEN is presented:
//   • FORT_KEY        the owner. Issues ACTIVE cards, approves/unfreezes, stores secrets, rotates.
//   • FORT_AGENT_KEY  (optional) an agent. May request/use/freeze/revoke — but a card it
//                     issues is PENDING (inert) until the owner approves it in the wallet.
// If FORT_AGENT_KEY is unset, only the owner token works and every issue is active (the old
// single-token behaviour, unchanged).
//
// Every act writes a line to the STATEMENT — an append-only events ledger (GET /events). The
// ledger never contains a key or a secret value; it's the audit trail, not the vault.
//
// One file, no dependencies, runs on Cloudflare Workers. Fork it, read it, run your own.
//
// HTTP API (all routes require  Authorization: Bearer <FORT_KEY | FORT_AGENT_KEY>):
//   POST   /secrets            {name, value}                       store a secret (owner only)
//   POST   /rotate                                                 rotate the vault key (owner only)
//   POST   /cards              {name, secret, allowed_hosts, ...}  issue (owner) / request (agent)
//   GET    /cards                                                  list cards (never the key)
//   GET    /events             ?limit=N                            the statement (audit ledger)
//   POST   /cards/:id/use      {url, method?, headers?, body?}     charge: authorize + settle
//   POST   /cards/:id/freeze   {frozen}                            freeze (any) / unfreeze (owner)
//   DELETE /cards/:id                                              revoke
//
// Bindings (see wrangler.toml):
//   KV namespace `VAULT`
//   secret `FORT_KEY`        owner bearer token you choose
//   secret `FORT_AGENT_KEY`  (optional) agent bearer token — its issues land pending
//   secret `MASTER_KEY`      base64 of 32 random bytes:  openssl rand -base64 32
//   var    `FORT_SPACE`      (optional) the space for the owner/agent token (default "owner")
//   var    `NOTIFY_WEBHOOK`  (optional) URL that gets a JSON POST when an agent requests a card
//                            (best-effort; the hosted Core fans this out to email + web-push)

import { handleAuth, resolveSession, oauthConfigured } from "./auth.js";
import { handlePasskey, requireStepUp } from "./webauthn.js";
import { resolveAgentBearer, mintAgentBearer, listAgents, revokeAgent } from "./agents.js";
import { handleApp } from "./app.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });

const HUMAN_REQUIRED =
  "Human-in-the-loop required: issuing or re-authorizing a Fort Card is an owner act. " +
  "Present the owner token (FORT_KEY) to do it — an agent token cannot issue an active " +
  "card, store a secret, refill its own allowance, or rotate the vault. (Agents may use, freeze, revoke.)";

// Every record is namespaced by the tenant's space — the hard isolation boundary. Deny by
// default: no key is ever read or written without a space in front of it.
const K = (space, ...parts) => space + ":" + parts.join(":");

// ── envelope encryption: MASTER_KEY is the KEK (the sovereign root — never rotated in-app);
// under it, each SPACE has its own rotatable DATA key (DEK) in KV, wrapped by the KEK. A tenant
// can mint a fresh DEK and re-seal their secrets (POST /rotate, owner only) without touching
// any other space — the KEK never changes, so a rotation can NEVER lock anyone out, and a
// leaked agent token can never re-key. A secret sealed before the space's first rotation carries
// no keyRef and still opens under the KEK. ──
async function kek(env) {
  return crypto.subtle.importKey("raw", b64d(env.MASTER_KEY), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
const dekCache = new Map(); // keyed by space:ref; rotation mints a new ref, so never stale
async function importRaw(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function loadDEK(env, space, ref) {
  const cacheKey = space + ":" + ref;
  if (dekCache.has(cacheKey)) return dekCache.get(cacheKey);
  const raw = await env.VAULT.get(K(space, "dek", ref));
  if (!raw) throw new Error("vault data key '" + ref + "' missing");
  const w = JSON.parse(raw);
  const dekRaw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(w.iv) }, await kek(env), b64d(w.ct));
  const key = await importRaw(new Uint8Array(dekRaw));
  dekCache.set(cacheKey, key);
  return key;
}
// key to SEAL new writes in a space with: that space's active DEK once rotated, else the KEK
// (pre-rotation = original behaviour). key to OPEN a secret: its keyRef's DEK, else the KEK.
async function writeKey(env, space) {
  const ref = await env.VAULT.get(K(space, "dek", "active"));
  return ref ? { key: await loadDEK(env, space, ref), ref } : { key: await kek(env), ref: null };
}
async function readKey(env, space, keyRef) {
  return keyRef ? loadDEK(env, space, keyRef) : kek(env);
}
async function sealWith(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { iv: b64e(iv.buffer), ct: b64e(ct) };
}
async function encrypt(env, space, plaintext) {
  const { key, ref } = await writeKey(env, space);
  const s = await sealWith(key, plaintext);
  if (ref) s.keyRef = ref;
  return s;
}
async function decrypt(env, space, s) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(s.iv) }, await readKey(env, space, s.keyRef), b64d(s.ct));
  return dec.decode(pt);
}
// Mint a fresh DEK for ONE space, wrap it under the KEK, make it active, and re-seal that
// space's secrets to it. Other spaces and the KEK are untouched. Owner-gated by the route.
async function rotateDataKey(env, space) {
  const rawDek = crypto.getRandomValues(new Uint8Array(32));
  const ref = "dek_" + crypto.randomUUID().slice(0, 8);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await kek(env), rawDek);
  await env.VAULT.put(K(space, "dek", ref), JSON.stringify({ ref, iv: b64e(iv.buffer), ct: b64e(wrapped), created: new Date().toISOString() }));
  const newKey = await importRaw(rawDek);
  dekCache.set(space + ":" + ref, newKey);
  await env.VAULT.put(K(space, "dek", "active"), ref); // active before re-seal, so concurrent writes land here too
  let rotated = 0;
  let cursor;
  const prefix = K(space, "secret", "");
  do {
    const page = await env.VAULT.list({ prefix, cursor });
    for (const k of page.keys) {
      const raw = await env.VAULT.get(k.name);
      if (!raw) continue;
      const plain = await decrypt(env, space, JSON.parse(raw)); // opens under its OLD keyRef / the KEK
      const sealed = await sealWith(newKey, plain);
      sealed.keyRef = ref;
      await env.VAULT.put(k.name, JSON.stringify(sealed));
      rotated++;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return { ref, rotated };
}

// ── the statement: an append-only ledger of every act (never a key, never a secret value) ──
async function logEvent(env, space, type, data) {
  const ts = new Date().toISOString();
  // ts in the key → KV lists lexicographically, so we read newest-first by reversing.
  await env.VAULT.put(K(space, "event", ts, crypto.randomUUID().slice(0, 8)), JSON.stringify({ ts, type, ...data }));
}

// ── SPLIT DEPLOY: the last mile (decrypt + inject + fetch) can be delegated to a separate
// worker on the OWNER's own Cloudflare. When LAST_MILE_URL + LAST_MILE_KEY are set, THIS worker
// (the control plane) holds only ciphertext and never touches MASTER_KEY — it relays sealed
// material to the last-mile worker, which opens it on the owner's infra. Unset = single-worker
// self-host (decrypt inline, the original behaviour). See src/last-mile.js. ──
function splitMode(env) {
  return !!(env.LAST_MILE_URL && env.LAST_MILE_KEY);
}
async function callLastMile(env, path, payload) {
  const resp = await fetch(env.LAST_MILE_URL.replace(/\/+$/, "") + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + env.LAST_MILE_KEY },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error("last-mile " + path + " failed: " + resp.status);
  return resp.json();
}
// the space's active KEK-wrapped DEK ({iv, ct}) to hand the last-mile worker, or null pre-rotation.
async function activeWrappedDEK(env, space) {
  const ref = await env.VAULT.get(K(space, "dek", "active"));
  if (!ref) return null;
  const raw = await env.VAULT.get(K(space, "dek", ref));
  return raw ? JSON.parse(raw) : null;
}
// the KEK-wrapped DEK for a secret's specific keyRef (what opens THAT secret), or null.
async function wrappedDEKFor(env, space, keyRef) {
  if (!keyRef) return null;
  const raw = await env.VAULT.get(K(space, "dek", keyRef));
  return raw ? JSON.parse(raw) : null;
}

// best-effort owner notification when an agent requests a card; never blocks issuance.
async function notifyCardRequest(env, card) {
  if (!env.NOTIFY_WEBHOOK) return;
  const limit = card.limit != null ? String(card.limit) : "unlimited";
  try {
    await fetch(env.NOTIFY_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "fort-card.request",
        text: `Fort Card approval needed: ${card.name} → ${card.allowed_hosts.join(", ")} (limit ${limit})`,
        card: { id: card.id, name: card.name, secret: card.secret, allowed_hosts: card.allowed_hosts, limit: card.limit },
      }),
    });
  } catch {
    /* never block card creation on a notification */
  }
}

// ── SSRF guard: refuse private / loopback / link-local / cloud-metadata targets. The card's
// allowed_hosts is the merchant allowlist; this is the second, network-layer fence, enforced at
// the control plane BEFORE a charge so a misconfigured card can never point the key at an internal
// address. (The last-mile worker re-checks this too — belt and suspenders.) ──
export function ssrfBlocked(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "::1" || h === "0.0.0.0" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 127 || a === 10 || a === 0) return true; // loopback / private / this-host
    if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
    if (a === 192 && b === 168) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  }
  return false;
}

export default {
  async fetch(request, env) {
    // Crypto must be available (MASTER_KEY, or a delegated last mile in split mode), and at least
    // one way to authenticate: the self-host owner token (FORT_KEY) and/or GitHub-App OAuth login
    // (the SaaS path). A pure self-host sets FORT_KEY; a managed instance configures OAuth.
    const cryptoReady = env.MASTER_KEY || splitMode(env);
    const authReady = env.FORT_KEY || oauthConfigured(env);
    if (!cryptoReady || !authReady) {
      return json({ error: "server not configured — need MASTER_KEY (or LAST_MILE_URL + LAST_MILE_KEY), and FORT_KEY or the GitHub-App OAuth vars (GH_CLIENT_ID/SECRET/CALLBACK_URL)" }, 500);
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/") return json({ name: "fort-card", ok: true, docs: "https://github.com/TheFortThatHolds/fort-card" });

    // The wallet PWA (and its manifest / service worker). Public HTML — the page itself drives
    // auth via /whoami. This same page is what Fort Core embeds as the plugin (?embed=1).
    const appResp = handleApp(env, request, url, path);
    if (appResp) return appResp;

    // Identity routes (login / callback / logout / whoami). When OAuth is unconfigured these
    // don't exist and handleAuth returns null — the self-host bearer path below is unchanged.
    const authResp = await handleAuth(request, env, url, path);
    if (authResp) return authResp;

    // WHO is calling, and WHICH space do they operate in?
    //   • OAuth session   → a verified SaaS tenant, operating in their OWN identity-born space.
    //   • FORT_KEY        → the self-host owner (single-tenant, `FORT_SPACE`).
    //   • minted bearer   → an agent the owner provisioned (resolves to its own space).
    //   • FORT_AGENT_KEY  → the self-host single agent (legacy/self-host space).
    const session = await resolveSession(request, env);
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const ownerToken = !!env.FORT_KEY && bearer === env.FORT_KEY;
    const legacyAgent = !!env.FORT_AGENT_KEY && bearer === env.FORT_AGENT_KEY;
    // A minted bearer carries its own space; only resolve it when it isn't an owner/legacy token.
    const mintedAgent = !session && !ownerToken && !legacyAgent ? await resolveAgentBearer(env, bearer) : null;
    const agent = legacyAgent || !!mintedAgent;
    const human = !!session || ownerToken;
    if (!session && !ownerToken && !agent) return json({ error: "unauthorized" }, 401);
    const space = session ? session.space : mintedAgent ? mintedAgent.space : env.FORT_SPACE || "owner";

    // Passkey enroll + per-action step-up — the banking-app gate. Only an authenticated human in a
    // space reaches these; OAuth-unconfigured self-host never hits them (no session, owner uses a token).
    const pkResp = await handlePasskey(env, request, url, path, human ? { space, human, login: session ? session.login : "owner" } : null);
    if (pkResp) return pkResp;

    // Owner acts by an OAuth human (a browser session) demand a FRESH passkey tap, EACH TIME
    // (DESIGN §3): the route requires an X-Fort-Action step-up token scoped to this act. A self-host
    // owner presenting FORT_KEY is an API token, not a browser human, so it is not step-up-gated.
    const stepIfSession = async (action) => (session ? requireStepUp(env, request, space, action) : null);

    const body = request.method === "GET" ? {} : await request.json().catch(() => ({}));

    // ── agents: mint / list / revoke scoped bearers (mint + revoke are owner acts, step-up gated) ──
    if (path === "/agents" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      const s = await stepIfSession("agent.mint");
      if (s) return s;
      const minted = await mintAgentBearer(env, space, { label: body.label, ttl_days: body.ttl_days });
      await logEvent(env, space, "agent.mint", { id: minted.id, label: minted.label, expires_at: minted.expires_at });
      return json({ ...minted, note: "This token is shown ONCE. Store it now; it cannot be recovered." });
    }
    if (path === "/agents" && request.method === "GET") {
      return json({ agents: await listAgents(env, space) });
    }
    {
      const am = path.match(/^\/agents\/([^/]+)$/);
      if (am && request.method === "DELETE") {
        if (!human) return json({ error: HUMAN_REQUIRED }, 403);
        const s = await stepIfSession("agent.revoke");
        if (s) return s;
        const r = await revokeAgent(env, space, am[1]);
        if (r.error) return json(r, 404);
        await logEvent(env, space, "agent.revoke", { id: am[1] });
        return json(r);
      }
    }

    // ── store a secret (owner only — seeding a real key into the vault is a human act) ──
    if (path === "/secrets" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      const s = await stepIfSession("secret.store");
      if (s) return s;
      if (!body.name || !body.value) return json({ error: "name and value required" }, 400);
      let sealed;
      if (splitMode(env)) {
        // seal on the owner's last-mile worker; the control plane only stores the ciphertext.
        const ref = await env.VAULT.get(K(space, "dek", "active"));
        const { sealed: s } = await callLastMile(env, "/seal", { plaintext: String(body.value), dek: await activeWrappedDEK(env, space) });
        if (ref) s.keyRef = ref; // tag it with the DEK that opens it (the last-mile sealed under that DEK)
        sealed = s;
      } else {
        sealed = await encrypt(env, space, String(body.value));
      }
      await env.VAULT.put(K(space, "secret", body.name), JSON.stringify(sealed));
      await logEvent(env, space, "secret.store", { name: body.name }); // name only — never the value
      return json({ ok: true, name: body.name });
    }

    // ── rotate this space's vault key (owner only): mint a new DEK + re-seal every secret. The
    // MASTER_KEY (sovereign root) is untouched, so this can never lock the owner out, and an
    // agent token can never trigger it. The owner generates; only the owner commits. ──
    if (path === "/rotate" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      const s = await stepIfSession("vault.rotate");
      if (s) return s;
      let res;
      if (splitMode(env)) {
        // gather every sealed secret + the current active wrapped DEK, hand them to the last-mile
        // worker to re-seal under a fresh DEK, then persist what comes back. Plaintext stays there.
        const secrets = [];
        let cursor;
        const prefix = K(space, "secret", "");
        do {
          const page = await env.VAULT.list({ prefix, cursor });
          for (const k of page.keys) {
            const raw = await env.VAULT.get(k.name);
            if (raw) secrets.push({ name: k.name.slice(prefix.length), sealed: JSON.parse(raw) });
          }
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
        const out = await callLastMile(env, "/rotate", { secrets, dek: await activeWrappedDEK(env, space) });
        await env.VAULT.put(K(space, "dek", out.dek.ref), JSON.stringify({ ...out.dek, created: new Date().toISOString() }));
        await env.VAULT.put(K(space, "dek", "active"), out.dek.ref);
        for (const s of out.secrets) await env.VAULT.put(K(space, "secret", s.name), JSON.stringify(s.sealed));
        res = { ref: out.dek.ref, rotated: out.secrets.length };
      } else {
        res = await rotateDataKey(env, space);
      }
      await logEvent(env, space, "vault.rotate", { ref: res.ref, rotated: res.rotated });
      return json({ ok: true, ...res });
    }

    // ── issue a card (owner → active; agent → pending, inert until the owner approves) ──
    if (path === "/cards" && request.method === "POST") {
      if (!body.name || !body.secret || !Array.isArray(body.allowed_hosts) || body.allowed_hosts.length === 0) {
        return json({ error: "name, secret, and a non-empty allowed_hosts array are required" }, 400);
      }
      const pending = !human; // an agent can ask, but never mint its own live allowance
      if (!pending) {
        // a human issuing an ACTIVE card is an owner act — fresh tap (sessions only).
        const s = await stepIfSession("card.issue");
        if (s) return s;
      }
      const id = "card_" + crypto.randomUUID().slice(0, 8);
      const card = {
        id,
        name: body.name,
        secret: body.secret,
        holder: body.holder || null,
        allowed_hosts: body.allowed_hosts.map(String),
        header: body.header || "Authorization",
        header_prefix: body.header_prefix ?? "Bearer ",
        limit: typeof body.limit === "number" ? body.limit : null,
        used: 0,
        expires_at: body.expires_at || null,
        frozen: pending, // pending cards are inert until approved
        pending,
        created: new Date().toISOString(),
      };
      await env.VAULT.put(K(space, "card", id), JSON.stringify(card));
      await logEvent(env, space, pending ? "card.request" : "card.issue", {
        id, name: card.name, secret: card.secret, holder: card.holder, allowed_hosts: card.allowed_hosts, limit: card.limit, pending,
      });
      if (pending) await notifyCardRequest(env, card);
      return json(card);
    }

    // ── list cards (the statement's subjects — never the underlying key) ──
    if (path === "/cards" && request.method === "GET") {
      const list = await env.VAULT.list({ prefix: K(space, "card", "") });
      const cards = [];
      for (const k of list.keys) {
        const c = JSON.parse(await env.VAULT.get(k.name));
        cards.push({
          id: c.id, name: c.name, secret: c.secret, holder: c.holder ?? null, allowed_hosts: c.allowed_hosts,
          limit: c.limit, used: c.used, remaining: c.limit != null ? Math.max(0, c.limit - c.used) : null,
          expires_at: c.expires_at, frozen: c.frozen, pending: c.pending || false,
        });
      }
      return json({ cards });
    }

    // ── the statement: read the append-only audit ledger (newest first) ──
    if (path === "/events" && request.method === "GET") {
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "100", 10) || 100, 1000);
      const list = await env.VAULT.list({ prefix: K(space, "event", "") });
      const keys = list.keys.map((k) => k.name).sort().reverse().slice(0, limit);
      const events = [];
      for (const name of keys) {
        const raw = await env.VAULT.get(name);
        if (raw) events.push(JSON.parse(raw));
      }
      return json({ events });
    }

    // ── /cards/:id  (use · freeze · revoke) ──
    const m = path.match(/^\/cards\/([^/]+)(\/use|\/freeze)?$/);
    if (m) {
      const id = m[1];
      const sub = m[2];
      const raw = await env.VAULT.get(K(space, "card", id));
      if (!raw) return json({ error: "no such card" }, 404);
      const card = JSON.parse(raw);

      if (sub === "/freeze" && request.method === "POST") {
        const frozen = !!body.frozen;
        // Freezing (kill switch) is a de-escalation any holder may do. UNFREEZING re-authorizes
        // a card — owner only — and unfreezing a PENDING card is how the owner approves it.
        if (!frozen && !human) return json({ error: HUMAN_REQUIRED }, 403);
        if (!frozen) {
          const s = await stepIfSession("card.approve");
          if (s) return s;
        }
        const approved = !frozen && !!card.pending;
        card.frozen = frozen;
        if (!frozen) card.pending = false;
        await env.VAULT.put(K(space, "card", id), JSON.stringify(card));
        await logEvent(env, space, frozen ? "card.freeze" : approved ? "card.approve" : "card.unfreeze", { id });
        return json({ id, frozen: card.frozen, pending: card.pending || false });
      }
      if (!sub && request.method === "DELETE") {
        await env.VAULT.delete(K(space, "card", id));
        await logEvent(env, space, "card.revoke", { id });
        return json({ revoked: id });
      }
      if (sub === "/use" && request.method === "POST") {
        // authorize (ISO-8583 in spirit) — a decline is still a line on the statement
        const decline = async (reason) => {
          await logEvent(env, space, "card.decline", { id, reason });
          return json({ authorized: false, decline_reason: reason });
        };
        if (card.pending) return decline("card pending owner approval (approve it in the wallet)");
        if (card.frozen) return decline("card frozen");
        if (card.expires_at && Date.parse(card.expires_at) < Date.now()) return decline("card expired");
        if (card.limit != null && card.used >= card.limit) return decline("limit reached");
        if (!body.url) return decline("request url required");
        let host;
        try { host = new URL(body.url).host; } catch { return decline("bad url"); }
        if (ssrfBlocked(host)) return decline(`host ${host} blocked (SSRF: private/loopback/link-local)`);
        if (!card.allowed_hosts.includes(host)) return decline(`host ${host} not allowed for this card`);

        // settle: the real key is injected server-side and ONLY the response comes back. In split
        // mode the control plane never opens the secret — it relays the ciphertext to the owner's
        // last-mile worker, which decrypts + injects + fetches on the owner's own infra.
        const secRaw = await env.VAULT.get(K(space, "secret", card.secret));
        if (!secRaw) return decline("secret missing from vault");
        const sealed = JSON.parse(secRaw);
        let resp, out;
        if (splitMode(env)) {
          const r = await callLastMile(env, "/charge", {
            secret: sealed,
            dek: await wrappedDEKFor(env, space, sealed.keyRef),
            header: card.header,
            header_prefix: card.header_prefix,
            request: { url: body.url, method: body.method || "GET", headers: body.headers || {}, body: body.body },
          });
          resp = { status: r.status };
          out = r.body;
        } else {
          const key = await decrypt(env, space, sealed);
          const httpResp = await fetch(body.url, {
            method: body.method || "GET",
            headers: { ...(body.headers || {}), [card.header]: card.header_prefix + key }, // credential injected LAST
            body: body.body == null ? undefined : typeof body.body === "string" ? body.body : JSON.stringify(body.body),
          });
          const text = await httpResp.text();
          try { out = JSON.parse(text); } catch { out = text; }
          resp = { status: httpResp.status };
        }
        card.used++;
        await env.VAULT.put(K(space, "card", id), JSON.stringify(card));
        await logEvent(env, space, "card.charge", { id, host, status: resp.status });
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
