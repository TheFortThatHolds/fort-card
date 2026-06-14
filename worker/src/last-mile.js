// Fort Card — the LAST-MILE worker.
//
// This is the thin, stateless half of a SPLIT deployment. Its one job is the last mile of a
// charge: take a SEALED secret, open it with the LOCAL master key, inject it into a single
// outbound request, and return only the response. It runs on the SECRET OWNER's own Cloudflare
// account and holds the owner's MASTER_KEY (the KEK). It holds NO long-term state — no cards,
// no statement, no UI, no secret storage. It is pure crypto + one fetch.
//
// WHY IT EXISTS. In a single-worker deploy, the same worker that stores the vault also decrypts
// and injects the key — so whoever operates that worker sees the plaintext key at injection
// time. That's fine for SELF-HOST (you are the operator). It is NOT fine for a MANAGED service:
// the operator would see your keys. Splitting the last mile out fixes that cryptographically:
//
//   • CONTROL PLANE (the managed worker, src/worker.js with LAST_MILE_URL set) holds ONLY
//     ciphertext — sealed secrets, KEK-wrapped DEKs, cards, the statement. It has NO MASTER_KEY,
//     so it CANNOT decrypt anything. It can only relay ciphertext here.
//   • LAST-MILE WORKER (this file, on the OWNER's Cloudflare) holds MASTER_KEY. It opens the
//     ciphertext, injects the key, makes the call, returns the response — all on the owner's
//     own infrastructure. The control-plane operator never holds the plaintext.
//
// The envelope format is identical to the main worker (AES-256-GCM; per-space DEK wrapped under
// the KEK), so a secret sealed by either side opens on the other. The control plane sends the
// sealed secret and — if the secret carries a keyRef — the KEK-wrapped DEK alongside it; this
// worker unwraps the DEK with MASTER_KEY, opens the secret, and is done.
//
// One file, no dependencies, runs on Cloudflare Workers. Deploy it to YOUR account, hand its
// URL + a shared bearer (LAST_MILE_KEY) to the control plane, and your keys never leave home.
//
// HTTP API (all routes require  Authorization: Bearer <LAST_MILE_KEY>):
//   GET    /                                                 identity / health
//   POST   /seal     {plaintext, dek?}                       seal a value → {iv, ct}
//   POST   /charge   {secret, dek?, request, header, ...}    decrypt + inject + fetch → response
//   POST   /rotate   {secrets[], dek?}                       mint a fresh DEK, re-seal every secret
//
// Bindings (see last-mile.wrangler.toml):
//   secret `MASTER_KEY`     base64 of 32 random bytes:  openssl rand -base64 32   (the KEK — yours)
//   secret `LAST_MILE_KEY`  the shared bearer the control plane presents to call this worker

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });

// ── envelope crypto — same shape as the control plane ──
async function kek(env) {
  return crypto.subtle.importKey("raw", b64d(env.MASTER_KEY), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function importRaw(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
// Unwrap a KEK-wrapped DEK ({iv, ct}) → an AES-GCM key. No DEK means the secret was sealed under
// the KEK directly (pre-rotation), so we hand back the KEK itself.
async function openKey(env, dek) {
  if (!dek) return kek(env);
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(dek.iv) }, await kek(env), b64d(dek.ct));
  return importRaw(new Uint8Array(raw));
}
async function sealWith(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { iv: b64e(iv.buffer), ct: b64e(ct) };
}
async function openWith(key, sealed) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(sealed.iv) }, key, b64d(sealed.ct));
  return dec.decode(pt);
}

// ── SSRF guard: this worker makes the outbound call, so it's the right place to refuse private,
// loopback, link-local, and cloud-metadata targets. Host allow-listing happens on the control
// plane (the card's allowed_hosts); this is the second, network-layer fence. ──
function ssrfBlocked(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "::1" || h === "0.0.0.0" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 127 || a === 10 || a === 0) return true;             // loopback / private / this-host
    if (a === 169 && b === 254) return true;                       // link-local + cloud metadata (169.254.169.254)
    if (a === 192 && b === 168) return true;                       // private
    if (a === 172 && b >= 16 && b <= 31) return true;              // private
    if (a === 100 && b >= 64 && b <= 127) return true;             // carrier-grade NAT
  }
  return false;
}

export default {
  async fetch(request, env) {
    if (!env.MASTER_KEY || !env.LAST_MILE_KEY) {
      return json({ error: "server not configured — set MASTER_KEY and LAST_MILE_KEY secrets" }, 500);
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/") {
      return json({ name: "fort-card-last-mile", ok: true, role: "decrypt+inject on the owner's own infra" });
    }

    // Single shared bearer: the control plane presents it on every call. This worker trusts the
    // caller to have already enforced card rules (frozen/expired/limit/host) — its own guarantee
    // is narrower and non-negotiable: it never returns a decrypted key, only the upstream response,
    // and it refuses SSRF targets.
    if ((request.headers.get("Authorization") || "") !== "Bearer " + env.LAST_MILE_KEY) {
      return json({ error: "unauthorized" }, 401);
    }
    const body = request.method === "GET" ? {} : await request.json().catch(() => ({}));

    // ── seal a plaintext value under the owner's active DEK (or the KEK if none) → ciphertext the
    // control plane stores. Plaintext is sealed HERE, on the owner's infra; the control plane only
    // ever persists what comes back. ──
    if (path === "/seal" && request.method === "POST") {
      if (typeof body.plaintext !== "string") return json({ error: "plaintext (string) required" }, 400);
      const sealed = await sealWith(await openKey(env, body.dek || null), body.plaintext);
      return json({ sealed });
    }

    // ── the charge: open the sealed secret, inject it into ONE outbound request, return only the
    // response. The credential header is injected LAST so a caller-supplied header can't override
    // or strip it. The plaintext key never leaves this worker. ──
    if (path === "/charge" && request.method === "POST") {
      const req = body.request || {};
      if (!body.secret || !req.url) return json({ error: "secret and request.url required" }, 400);
      let host;
      try { host = new URL(req.url).host; } catch { return json({ error: "bad request.url" }, 400); }
      if (ssrfBlocked(host)) return json({ error: `host ${host} blocked (SSRF)` }, 403);

      const key = await openWith(await openKey(env, body.dek || null), body.secret);
      const header = body.header || "Authorization";
      const prefix = body.header_prefix ?? "Bearer ";
      const resp = await fetch(req.url, {
        method: req.method || "GET",
        headers: { ...(req.headers || {}), [header]: prefix + key }, // credential injected LAST
        body: req.body == null ? undefined : typeof req.body === "string" ? req.body : JSON.stringify(req.body),
      });
      const text = await resp.text();
      let out;
      try { out = JSON.parse(text); } catch { out = text; }
      return json({ status: resp.status, body: out });
    }

    // ── rotate: mint a fresh DEK (wrapped under the KEK), re-seal every secret the control plane
    // hands over, and return the new wrapped DEK + re-sealed secrets for the control plane to
    // persist. Plaintext exists only inside this worker for the duration of the re-seal. ──
    if (path === "/rotate" && request.method === "POST") {
      const secrets = Array.isArray(body.secrets) ? body.secrets : [];
      const oldKey = await openKey(env, body.dek || null);
      const rawDek = crypto.getRandomValues(new Uint8Array(32));
      const newKey = await importRaw(rawDek);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await kek(env), rawDek);
      const ref = "dek_" + crypto.randomUUID().slice(0, 8);
      const out = [];
      for (const s of secrets) {
        if (!s || !s.name || !s.sealed) continue;
        const plain = await openWith(oldKey, s.sealed);
        const sealed = await sealWith(newKey, plain);
        sealed.keyRef = ref;
        out.push({ name: s.name, sealed });
      }
      return json({ ref, dek: { ref, iv: b64e(iv.buffer), ct: b64e(wrapped) }, secrets: out });
    }

    return json({ error: "not found" }, 404);
  },
};
