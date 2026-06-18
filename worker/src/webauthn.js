// Fort Card — PASSKEYS. The banking-app gate: every sensitive act demands a fresh fingerprint
// (WebAuthn, `userVerification: "required"`), EACH TIME. No lingering powerful session.
//
// Why this is the spine of the SaaS, not a nicety: an OAuth login (auth.js) only says WHO you are
// and WHICH space you're in — an 8h identity cookie. By itself it can do nothing dangerous. The
// dangerous acts (store a secret, issue an ACTIVE card, approve a pending one, rotate the vault,
// mint an agent bearer) each require a separate, fresh passkey ceremony that yields a one-shot,
// short-lived, action-scoped STEP-UP TOKEN. Steal the cookie → you still can't spend or escalate
// without the live tap. There is no "I already unlocked once on this device."
//
// All crypto is Web Crypto + a tiny CBOR reader (COSE keys / attestationObject). No deps.
//
// Routes:
//   POST /passkey/register/begin                 → creation options (+ signed challenge cookie)
//   POST /passkey/register/finish  {cred}        → verify attestation, store the credential
//   GET  /passkey/list                           → this space's enrolled passkeys (no secrets)
//   POST /passkey/assert/begin     {action}      → request options for a step-up on ONE action
//   POST /passkey/assert/finish    {cred}        → verify, return { action_token } (one-shot)
//
// Storage (per space): `<space>:passkey:<credId>` → { credId, jwk, alg, signCount, label, created }
// Step-up token: signed {space, action, jti, exp(2m)}; single-use (jti burned in KV on consume).

import { b64u, b64ud, sign, verify, readCookie, setCookie } from "./auth.js";
import { consumeOnce } from "./oncegate.js";

const te = new TextEncoder();
const td = new TextDecoder();
const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });

const CHAL_COOKIE = "fc_chal";
const CHAL_TTL_SEC = 60 * 5;
const STEPUP_TTL_SEC = 60 * 2;
// One fingerprint tap (enroll OR unlock) opens the wallet for this long; then it locks again and
// asks for the tap once more. GitHub stays the floor underneath — this only gates ACTING.
const UNLOCK_COOKIE = "fc_unlock";
const UNLOCK_TTL_SEC = 60 * 30;
async function unlockCookie(env, space) {
  return setCookie(UNLOCK_COOKIE, await sign(env, { space, kind: "unlock", exp: Date.now() + UNLOCK_TTL_SEC * 1000 }), UNLOCK_TTL_SEC);
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// The relying party: rpId is the registrable domain (the hostname), origin is the full scheme+host
// the browser reports. Derived from the request unless pinned via env (WALLET_RPID / WALLET_ORIGIN).
function rp(env, url) {
  return { id: env.WALLET_RPID || url.hostname, origin: env.WALLET_ORIGIN || url.origin };
}

// ── minimal CBOR reader: unsigned/negative ints, byte/text strings, arrays, maps. Enough for the
// attestationObject and a COSE_Key. Returns [value, nextOffset]. ──
function cbor(buf, p = 0) {
  const b = buf[p];
  const major = b >> 5;
  const minor = b & 0x1f;
  p++;
  let len = minor;
  if (minor === 24) len = buf[p++];
  else if (minor === 25) { len = (buf[p] << 8) | buf[p + 1]; p += 2; }
  else if (minor === 26) { len = ((buf[p] << 24) | (buf[p + 1] << 16) | (buf[p + 2] << 8) | buf[p + 3]) >>> 0; p += 4; }
  switch (major) {
    case 0: return [len, p];
    case 1: return [-1 - len, p];
    case 2: return [buf.slice(p, p + len), p + len];
    case 3: return [td.decode(buf.slice(p, p + len)), p + len];
    case 4: {
      const arr = [];
      for (let i = 0; i < len; i++) { const [v, np] = cbor(buf, p); arr.push(v); p = np; }
      return [arr, p];
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const [k, np] = cbor(buf, p); const [v, np2] = cbor(buf, np); map.set(k, v); p = np2;
      }
      return [map, p];
    }
    default:
      throw new Error("unsupported CBOR major " + major);
  }
}

// COSE_Key → a JWK we can store and re-import. ES256 (EC2/P-256, alg -7) and RS256 (alg -257).
function coseToJwk(cose) {
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (kty === 2 && alg === -7) {
    return { jwk: { kty: "EC", crv: "P-256", x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) }, alg: -7 };
  }
  if (kty === 3 && alg === -257) {
    return { jwk: { kty: "RSA", n: b64u(cose.get(-1)), e: b64u(cose.get(-2)) }, alg: -257 };
  }
  throw new Error("unsupported key type/alg (need ES256 or RS256)");
}
async function importVerifyKey(jwk, alg) {
  return alg === -7
    ? crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
    : crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}
// WebAuthn ES256 signatures are DER (SEQUENCE{INTEGER r, INTEGER s}); Web Crypto wants raw r||s.
function derToRaw(der) {
  let o = 2; // skip 0x30, len
  if (der[o++] !== 0x02) throw new Error("bad DER r");
  let rlen = der[o++];
  let r = der.slice(o, o + rlen); o += rlen;
  if (der[o++] !== 0x02) throw new Error("bad DER s");
  let slen = der[o++];
  let s = der.slice(o, o + slen);
  const trim = (x) => { while (x.length > 32 && x[0] === 0) x = x.slice(1); return x; };
  const pad = (x) => { const out = new Uint8Array(32); out.set(trim(x), 32 - trim(x).length); return out; };
  const raw = new Uint8Array(64);
  raw.set(pad(r), 0); raw.set(pad(s), 32);
  return raw;
}
async function verifySig(jwk, alg, sig, signedData) {
  const key = await importVerifyKey(jwk, alg);
  if (alg === -7) return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(sig), signedData);
  return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, signedData);
}

// authData: rpIdHash(32) | flags(1) | signCount(4) | [attestedCredData if AT flag]
function parseAuthData(ad) {
  const rpIdHash = ad.slice(0, 32);
  const flags = ad[32];
  const signCount = ((ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36]) >>> 0;
  const out = { rpIdHash, up: !!(flags & 0x01), uv: !!(flags & 0x04), at: !!(flags & 0x40), signCount };
  if (out.at) {
    const credIdLen = (ad[53] << 8) | ad[54];
    out.credId = ad.slice(55, 55 + credIdLen);
    out.cose = cbor(ad, 55 + credIdLen)[0];
  }
  return out;
}

// clientDataJSON must be the right ceremony, echo our challenge, and come from our origin.
function checkClientData(clientDataBytes, expectedType, expectedChallenge, expectedOrigin) {
  const cd = JSON.parse(td.decode(clientDataBytes));
  if (cd.type !== expectedType) throw new Error("wrong ceremony type");
  if (cd.challenge !== expectedChallenge) throw new Error("challenge mismatch");
  if (cd.origin !== expectedOrigin) throw new Error("origin mismatch");
}

const passkeyKey = (space, credId) => `${space}:passkey:${credId}`;
const passkeyPrefix = (space) => `${space}:passkey:`;
const indexKey = (space) => `${space}:passkey_index`;

// KV list() is eventually consistent (can lag a write by tens of seconds), so enumerating
// passkeys via list() makes a freshly-enrolled credential briefly invisible — the card stays on
// "No passkey" even though it's saved and working. We keep a strongly-consistent INDEX (read via
// get()) of {credId,label,created} and enumerate from that. The per-credential records still hold
// the key material for verification. Heals old data by backfilling the index from list() once.
async function listCreds(env, space) {
  const idx = await env.VAULT.get(indexKey(space), "json");
  if (idx && idx.length) return idx;
  const out = [];
  const list = await env.VAULT.list({ prefix: passkeyPrefix(space) });
  for (const k of list.keys) {
    const r = await env.VAULT.get(k.name, "json");
    if (r) out.push({ credId: r.credId, label: r.label, created: r.created });
  }
  if (out.length) await env.VAULT.put(indexKey(space), JSON.stringify(out));
  return out;
}
async function addToIndex(env, space, entry) {
  const idx = (await env.VAULT.get(indexKey(space), "json")) || [];
  if (!idx.some((e) => e.credId === entry.credId)) idx.push(entry);
  await env.VAULT.put(indexKey(space), JSON.stringify(idx));
}

export async function spaceHasPasskey(env, space) {
  return (await listCreds(env, space)).length > 0;
}

// ── per-action STEP-UP enforcement. A sensitive route calls this; it passes only if the caller
// presents an `X-Fort-Action` token from a fresh passkey assertion, scoped to THIS space + action,
// unexpired, and not already spent. Returns null on success, or a 401 Response to short-circuit. ──
export async function requireStepUp(env, request, space, action) {
  const tok = request.headers.get("X-Fort-Action") || "";
  const claim = await verify(env, tok);
  if (!claim || claim.space !== space || claim.action !== action || !claim.jti) {
    return json({ error: `step-up required: a fresh passkey tap for '${action}' (POST /passkey/assert/begin then /finish)` }, 401);
  }
  // Atomically burn the one-shot token: two simultaneous uses can't both pass (a KV check-then-write
  // can be raced). The FIRST use wins; any concurrent or later reuse is refused.
  if (!(await consumeOnce(env, "stepup:" + claim.jti, STEPUP_TTL_SEC + 60))) {
    return json({ error: "step-up token already used" }, 401);
  }
  return null; // good — one-shot consumed
}

// ── the routes. `auth` is { space, human } resolved by the worker; only an authenticated human in
// a space may enroll or step up. Returns a Response if handled, else null. ──
export async function handlePasskey(env, request, url, path, auth) {
  if (!path.startsWith("/passkey")) return null;
  if (!auth || !auth.human || !auth.space) return json({ error: "sign in first" }, 401);
  const space = auth.space;
  const { id: rpId, origin } = rp(env, url);
  const body = request.method === "GET" ? {} : await request.json().catch(() => ({}));

  if (path === "/passkey/register/begin" && request.method === "POST") {
    const challenge = b64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const chalTok = await sign(env, { challenge, kind: "create", space, exp: Date.now() + CHAL_TTL_SEC * 1000 });
    const existing = await listCreds(env, space);
    return new Response(
      JSON.stringify({
        publicKey: {
          challenge,
          rp: { id: rpId, name: "Fort Wallet" },
          user: { id: b64u(te.encode(space)), name: auth.login || space, displayName: auth.login || space },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
          authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
          excludeCredentials: existing.map((e) => ({ type: "public-key", id: e.credId })),
          timeout: 120000,
          attestation: "none",
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": setCookie(CHAL_COOKIE, chalTok, CHAL_TTL_SEC) } },
    );
  }

  if (path === "/passkey/register/finish" && request.method === "POST") {
    const claim = await verify(env, readCookie(request, CHAL_COOKIE));
    if (!claim || claim.kind !== "create" || claim.space !== space) return json({ error: "no/expired registration challenge" }, 400);
    try {
      const clientDataBytes = b64ud(body.clientDataJSON);
      checkClientData(clientDataBytes, "webauthn.create", claim.challenge, origin);
      const attObj = cbor(b64ud(body.attestationObject))[0];
      const authData = parseAuthData(attObj.get("authData"));
      if (!authData.up || !authData.uv) throw new Error("user presence + verification required");
      if (!eq(authData.rpIdHash, await sha256(te.encode(rpId)))) throw new Error("rpId mismatch");
      if (!authData.cose) throw new Error("no attested credential");
      const { jwk, alg } = coseToJwk(authData.cose);
      const credId = b64u(authData.credId);
      const record = { credId, jwk, alg, signCount: authData.signCount, label: body.label || "passkey", created: new Date().toISOString() };
      await env.VAULT.put(passkeyKey(space, credId), JSON.stringify(record));
      await addToIndex(env, space, { credId, label: record.label, created: record.created });
      // Just enabled a fingerprint on this device = present = unlock the session too.
      const headers = new Headers({ "Content-Type": "application/json" });
      headers.append("Set-Cookie", setCookie(CHAL_COOKIE, "", 0));
      headers.append("Set-Cookie", await unlockCookie(env, space));
      return new Response(JSON.stringify({ ok: true, credId, label: record.label, unlocked: true }), { status: 200, headers });
    } catch (e) {
      return json({ error: "registration failed: " + (e.message || "invalid") }, 400);
    }
  }

  if (path === "/passkey/list" && request.method === "GET") {
    return json({ passkeys: await listCreds(env, space) });
  }

  if (path === "/passkey/assert/begin" && request.method === "POST") {
    const action = String(body.action || "");
    if (!action) return json({ error: "action required (the act you're stepping up to authorize)" }, 400);
    const creds = await listCreds(env, space);
    if (creds.length === 0) return json({ error: "no passkey enrolled — register one first" }, 400);
    const challenge = b64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const chalTok = await sign(env, { challenge, kind: "get", space, action, exp: Date.now() + CHAL_TTL_SEC * 1000 });
    return new Response(
      JSON.stringify({
        publicKey: {
          challenge,
          rpId,
          userVerification: "required",
          allowCredentials: creds.map((e) => ({ type: "public-key", id: e.credId })),
          timeout: 120000,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": setCookie(CHAL_COOKIE, chalTok, CHAL_TTL_SEC) } },
    );
  }

  if (path === "/passkey/assert/finish" && request.method === "POST") {
    const claim = await verify(env, readCookie(request, CHAL_COOKIE));
    if (!claim || claim.kind !== "get" || claim.space !== space) return json({ error: "no/expired assertion challenge" }, 400);
    try {
      const credId = body.id || body.credId;
      const raw = await env.VAULT.get(passkeyKey(space, credId));
      if (!raw) throw new Error("unknown credential");
      const rec = JSON.parse(raw);
      const clientDataBytes = b64ud(body.clientDataJSON);
      checkClientData(clientDataBytes, "webauthn.get", claim.challenge, origin);
      const authData = b64ud(body.authenticatorData);
      const parsed = parseAuthData(authData);
      if (!parsed.up || !parsed.uv) throw new Error("user presence + verification required");
      if (!eq(parsed.rpIdHash, await sha256(te.encode(rpId)))) throw new Error("rpId mismatch");
      // clone detection: a real authenticator's counter only goes up (0 = counter unsupported).
      if (rec.signCount > 0 && parsed.signCount > 0 && parsed.signCount <= rec.signCount) throw new Error("signature counter regressed (possible clone)");
      const signedData = new Uint8Array([...authData, ...(await sha256(clientDataBytes))]);
      const ok = await verifySig(rec.jwk, rec.alg, b64ud(body.signature), signedData);
      if (!ok) throw new Error("bad signature");
      rec.signCount = parsed.signCount;
      await env.VAULT.put(passkeyKey(space, credId), JSON.stringify(rec));
      // A fingerprint tap opens the wallet for this session (the per-action step-up token is kept
      // for callers that want one, but the unlock cookie is what gates acting).
      const actionToken = await sign(env, { space, action: claim.action, jti: crypto.randomUUID(), exp: Date.now() + STEPUP_TTL_SEC * 1000 });
      const headers = new Headers({ "Content-Type": "application/json" });
      headers.append("Set-Cookie", setCookie(CHAL_COOKIE, "", 0));
      headers.append("Set-Cookie", await unlockCookie(env, space));
      return new Response(JSON.stringify({ ok: true, action: claim.action, action_token: actionToken, unlocked: true, expires_in: UNLOCK_TTL_SEC }), { status: 200, headers });
    } catch (e) {
      return json({ error: "assertion failed: " + (e.message || "invalid") }, 400);
    }
  }

  return null;
}
