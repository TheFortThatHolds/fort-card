// End-to-end WebAuthn roundtrip against the real handlePasskey + requireStepUp, with a simulated
// authenticator (node:crypto signs in DER, exactly like a real authenticator). Validates the CBOR
// reader, COSE→JWK, authData parsing, DER→raw, ES256 verification, challenge binding, and the
// one-shot step-up token. Run: node test/webauthn.test.mjs
import nodeCrypto from "node:crypto";
import { handlePasskey, requireStepUp } from "../src/webauthn.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

// ── minimal CBOR ENCODER (test-only; the worker only needs the decoder) ──
const cat = (...a) => { const t = a.reduce((n, x) => n + x.length, 0), o = new Uint8Array(t); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
function head(major, len) {
  if (len < 24) return new Uint8Array([(major << 5) | len]);
  if (len < 256) return new Uint8Array([(major << 5) | 24, len]);
  return new Uint8Array([(major << 5) | 25, len >> 8, len & 0xff]);
}
function cborEnc(v) {
  if (typeof v === "number" && Number.isInteger(v)) return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (typeof v === "string") { const b = new TextEncoder().encode(v); return cat(head(3, b.length), b); }
  if (Array.isArray(v)) return cat(head(4, v.length), ...v.map(cborEnc));
  if (v instanceof Map) { const parts = []; for (const [k, val] of v) parts.push(cborEnc(k), cborEnc(val)); return cat(head(5, v.size), ...parts); }
  throw new Error("cannot encode " + typeof v);
}

const b64u = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64ud = (s) => new Uint8Array(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

// ── fake KV (just enough of the Workers KV surface the modules use) ──
function fakeKV() {
  const m = new Map();
  return {
    async get(k, type) { const v = m.get(k); if (v == null) return null; return type === "json" ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : String(v)); },
    async delete(k) { m.delete(k); },
    async list({ prefix = "", limit = 1000 } = {}) { const keys = [...m.keys()].filter((k) => k.startsWith(prefix)).slice(0, limit).map((name) => ({ name })); return { keys, list_complete: true }; },
  };
}

const RP = "localhost", ORIGIN = "https://localhost", SPACE = "github:1";
const env = { VAULT: fakeKV(), SESSION_SECRET: "unit-test-secret", WALLET_RPID: RP, WALLET_ORIGIN: ORIGIN };
const AUTH = { space: SPACE, human: true, login: "octocat" };

const cookieOf = (resp) => { const sc = resp.headers.get("Set-Cookie") || ""; const m = sc.match(/fc_chal=([^;]*)/); return m ? decodeURIComponent(m[1]) : ""; };
const req = (path, bodyObj, cookie, extra = {}) =>
  new Request("https://localhost" + path, { method: "POST", headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: "fc_chal=" + cookie } : {}), ...extra }, body: JSON.stringify(bodyObj || {}) });
const call = (path, bodyObj, cookie, extra) => handlePasskey(env, req(path, bodyObj, cookie, extra), new URL("https://localhost" + path), path, AUTH);

(async () => {
  // simulated authenticator: one EC P-256 credential
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const nodePriv = nodeCrypto.createPrivateKey({ key: privJwk, format: "jwk" });
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const rpIdHash = await sha256(new TextEncoder().encode(RP));

  const coseKey = new Map([[1, 2], [3, -7], [-1, 1], [-2, b64ud(pubJwk.x)], [-3, b64ud(pubJwk.y)]]);
  const authDataRegister = cat(rpIdHash, new Uint8Array([0x45]), new Uint8Array([0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, credId.length]), credId, cborEnc(coseKey));
  const clientData = (type, challenge) => new TextEncoder().encode(JSON.stringify({ type, challenge, origin: ORIGIN }));

  console.log("register:");
  const rBegin = await call("/passkey/register/begin", {}, null);
  const rBeginJson = await rBegin.json();
  const regChallenge = rBeginJson.publicKey.challenge;
  ok(!!regChallenge && rBeginJson.publicKey.rp.id === RP, "begin returns options + challenge");
  const regChalCookie = cookieOf(rBegin);
  ok(!!regChalCookie, "begin sets the challenge cookie");

  const attObj = new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authDataRegister]]);
  const rFinish = await call("/passkey/register/finish", { clientDataJSON: b64u(clientData("webauthn.create", regChallenge)), attestationObject: b64u(cborEnc(attObj)) }, regChalCookie);
  const rFinishJson = await rFinish.json();
  ok(rFinish.status === 200 && rFinishJson.ok === true, "finish verifies attestation + stores the credential");
  ok(rFinishJson.credId === b64u(credId), "stored credId matches");

  console.log("assert / step-up:");
  const aBegin = await call("/passkey/assert/begin", { action: "secret.store" }, null);
  const aBeginJson = await aBegin.json();
  const assertChallenge = aBeginJson.publicKey.challenge;
  ok(aBeginJson.publicKey.allowCredentials.some((c) => c.id === b64u(credId)), "begin lists the enrolled credential");
  const assertChalCookie = cookieOf(aBegin);

  const authDataAssert = cat(rpIdHash, new Uint8Array([0x05]), new Uint8Array([0, 0, 0, 1])); // UP|UV, signCount=1
  const cd = clientData("webauthn.get", assertChallenge);
  const signedData = cat(authDataAssert, await sha256(cd));
  const derSig = new Uint8Array(nodeCrypto.sign("sha256", Buffer.from(signedData), { key: nodePriv, dsaEncoding: "der" }));
  const aFinish = await call("/passkey/assert/finish", { id: b64u(credId), clientDataJSON: b64u(cd), authenticatorData: b64u(authDataAssert), signature: b64u(derSig) }, assertChalCookie);
  const aFinishJson = await aFinish.json();
  ok(aFinish.status === 200 && !!aFinishJson.action_token, "finish verifies the ES256 signature + issues an action token");

  console.log("step-up enforcement:");
  const good = await requireStepUp(env, new Request("https://localhost/x", { headers: { "X-Fort-Action": aFinishJson.action_token } }), SPACE, "secret.store");
  ok(good === null, "valid step-up token passes for its action");
  const reused = await requireStepUp(env, new Request("https://localhost/x", { headers: { "X-Fort-Action": aFinishJson.action_token } }), SPACE, "secret.store");
  ok(reused !== null && reused.status === 401, "the same token is rejected on reuse (one-shot)");
  const wrongAction = await requireStepUp(env, new Request("https://localhost/x", { headers: { "X-Fort-Action": aFinishJson.action_token } }), SPACE, "vault.rotate");
  ok(wrongAction !== null, "token scoped to one action is rejected for another");

  console.log("tamper rejection:");
  const badSig = b64ud(b64u(derSig)); badSig[10] ^= 0xff;
  const aBegin2 = await call("/passkey/assert/begin", { action: "secret.store" }, null);
  const ch2 = (await aBegin2.json()).publicKey.challenge;
  const cookie2 = cookieOf(aBegin2);
  const cd2 = clientData("webauthn.get", ch2);
  const aFinishBad = await call("/passkey/assert/finish", { id: b64u(credId), clientDataJSON: b64u(cd2), authenticatorData: b64u(authDataAssert), signature: b64u(badSig) }, cookie2);
  ok(aFinishBad.status === 400, "a tampered signature is rejected");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
