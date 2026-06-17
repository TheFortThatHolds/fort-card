// Seal ticket — a short-TTL, HMAC-signed capability to seal ONE value at the tenant's own
// last-mile worker. The control plane (which holds the space's relay key) mints it; the last-mile
// (which holds the same key as its LAST_MILE_KEY) verifies it. It carries NO secret — it only
// authorizes a seal, so the plaintext key can travel browser → the tenant's last-mile directly and
// the control plane stays plaintext-blind. The relay key itself binds the ticket to that one
// last-mile, so the ticket needs no space/tenant field.
const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function hmac(relayKey, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(relayKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}

export async function mintSealTicket(relayKey, ttlSeconds = 120) {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const sig = await hmac(relayKey, nonce + ":" + exp);
  return [nonce, exp, sig].join(".");
}

export async function verifySealTicket(relayKey, ticket, now = Date.now()) {
  if (typeof ticket !== "string") return false;
  const parts = ticket.split(".");
  if (parts.length !== 3) return false;
  const [nonce, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp * 1000 < now) return false;
  const expect = await hmac(relayKey, nonce + ":" + exp);
  if (sig.length !== expect.length) return false; // length guard before constant-time compare
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expect.charCodeAt(i);
  return diff === 0;
}
