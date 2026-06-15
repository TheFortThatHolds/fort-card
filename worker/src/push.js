// Fort Card — WEB PUSH. So the owner's installed wallet (PWA) buzzes when an agent requests a
// card and it's waiting for approval. Implements RFC 8291 (aes128gcm payload encryption) + RFC
// 8292 (VAPID JWT auth) with WebCrypto — no library, runs native in the Worker.
//
// SELF-MINTING VAPID — nobody provisions keys. On first use the worker mints its own VAPID P-256
// keypair and stores it in KV (public shared with clients, private JWK kept server-side). Set
// VAPID_PUBLIC + VAPID_PRIVATE_JWK as Worker secrets to bring your own instead. Subscriptions are
// stored per space; a push is best-effort and prunes dead endpoints. Push never blocks issuance.

const enc = new TextEncoder();
const b64url = (b) => { const u = b instanceof Uint8Array ? b : new Uint8Array(b); let s = ""; for (const x of u) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const b64urlToBytes = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
const concat = (...arrs) => { const len = arrs.reduce((n, a) => n + a.length, 0); const out = new Uint8Array(len); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };

async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function hkdf(salt, ikm, info, len) {
  const prk = await hmac(salt, ikm);
  const t = await hmac(prk, concat(info, new Uint8Array([1])));
  return t.slice(0, len);
}

// ── self-minting VAPID keypair (or bring-your-own via secrets) ──
async function getVapid(env) {
  if (env.VAPID_PUBLIC && env.VAPID_PRIVATE_JWK) return { pub: env.VAPID_PUBLIC, jwk: JSON.parse(env.VAPID_PRIVATE_JWK) };
  const existing = await env.VAULT.get("_vapid", "json");
  if (existing) return existing;
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const v = { pub: b64url(pubRaw), jwk };
  await env.VAULT.put("_vapid", JSON.stringify(v));
  return v;
}
export async function vapidPublicKey(env) {
  return (await getVapid(env)).pub;
}

async function vapidAuthHeader(env, endpoint, vapid) {
  const origin = new URL(endpoint).origin;
  const header = b64url(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = b64url(enc.encode(JSON.stringify({ aud: origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || "mailto:owner@example.com" })));
  const signingInput = enc.encode(header + "." + payload);
  const key = await crypto.subtle.importKey("jwk", vapid.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, signingInput));
  return "vapid t=" + header + "." + payload + "." + b64url(sig) + ", k=" + vapid.pub;
}

async function encryptPayload(sub, payload) {
  const uaPublic = b64urlToBytes(sub.keys.p256dh);
  const authSecret = b64urlToBytes(sub.keys.auth);
  const asKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", asKeys.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asKeys.privateKey, 256));
  const ikm = await hkdf(authSecret, ecdhSecret, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const record = concat(payload, new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, record));
  const rs = 4096;
  const head = concat(salt, new Uint8Array([(rs >>> 24) & 255, (rs >>> 16) & 255, (rs >>> 8) & 255, rs & 255]), new Uint8Array([asPublic.length]), asPublic);
  return concat(head, ct);
}

async function sendWebPush(env, sub, payloadObj) {
  const vapid = await getVapid(env);
  const headers = { TTL: "86400", Authorization: await vapidAuthHeader(env, sub.endpoint, vapid) };
  let body;
  if (payloadObj != null) {
    body = await encryptPayload(sub, enc.encode(JSON.stringify(payloadObj)));
    headers["Content-Encoding"] = "aes128gcm";
    headers["Content-Type"] = "application/octet-stream";
  }
  const resp = await fetch(sub.endpoint, { method: "POST", headers, body });
  return resp.status;
}

// ── subscription storage (per space) ──
const subKey = (space, id) => `${space}:push:${id}`;
const subPrefix = (space) => `${space}:push:`;
async function subId(endpoint) { return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(endpoint)))).slice(0, 22); }

export async function addSubscription(env, space, sub) {
  if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) throw new Error("invalid subscription");
  const id = await subId(sub.endpoint);
  await env.VAULT.put(subKey(space, id), JSON.stringify({ endpoint: sub.endpoint, keys: sub.keys }));
  return { id };
}
export async function removeSubscription(env, space, endpoint) {
  if (endpoint) await env.VAULT.delete(subKey(space, await subId(endpoint)));
}
export async function listSubscriptions(env, space) {
  const list = await env.VAULT.list({ prefix: subPrefix(space), limit: 100 });
  const out = [];
  for (const k of list.keys) { const sub = await env.VAULT.get(k.name, "json"); if (sub) out.push({ id: k.name.slice(subPrefix(space).length), sub }); }
  return out;
}

// Best-effort fan-out to all the owner's devices; prune endpoints the push service retired.
export async function pushToOwner(env, space, note) {
  try {
    const subs = await listSubscriptions(env, space);
    for (const { id, sub } of subs) {
      try { const status = await sendWebPush(env, sub, note); if (status === 404 || status === 410) await env.VAULT.delete(subKey(space, id)); } catch { /* skip device */ }
    }
  } catch { /* never block on push */ }
}
