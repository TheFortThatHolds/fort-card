// Claim code — a one-time, short-TTL, space-bound token for the lockbox phone-home onboarding.
//
// The wallet mints a code (owner-gated) and shows it next to the Deploy button. The customer types
// it on Cloudflare's deploy screen; the freshly-deployed lockbox POSTs it back with its own URL
// (phone-home). That kills the URL copy-paste: the customer never copies a long workers.dev URL,
// they just type one short code.
//
// SECURITY:
//   • Stored HASHED, never in plaintext — we keep only SHA-256(code) → {space, exp}.
//   • Stored under a GLOBAL key (not space-scoped) on purpose: phone-home resolves the space FROM
//     the code (it doesn't know the space yet), so the lookup must be code → space.
//   • One-time: consumed (deleted) the instant it's used.
//   • Short-TTL: ~30 min, enforced on verify AND via KV expirationTtl (belt + suspenders).
//   • Phone-home lands PENDING — the owner's approve tap (passkey) is still the gate, so a leaked
//     or stray code can never silently bind a worker to a space.
const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// Unambiguous alphabet — no O/0/I/1, so a human can read it off one screen and type it on another.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 chars
export const DEFAULT_CLAIM_TTL = 30 * 60; // seconds

// SHA-256 → url-safe base64. Used for the at-rest hash of the code.
export async function sha256B64(s) {
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

// Normalize for hashing/lookup: strip formatting (dashes, spaces) and upper-case. So "abcd-efgh"
// and "ABCDEFGH" resolve identically — forgiving of how the customer types it.
export const normalizeClaim = (code) => String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

const claimKey = (hash) => "claim:" + hash;

// Generate a 16-char code (80 bits over a 32-char alphabet) formatted XXXX-XXXX-XXXX-XXXX.
function generateCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let out = "";
  for (let i = 0; i < 16; i++) out += ALPHABET[bytes[i] % ALPHABET.length];
  return out.replace(/(.{4})(.{4})(.{4})(.{4})/, "$1-$2-$3-$4");
}

// Mint a claim code for `space`. Returns the human-facing (formatted) code; only its hash is stored.
export async function mintClaimCode(env, space, ttlSeconds = DEFAULT_CLAIM_TTL) {
  const code = generateCode();
  const hash = await sha256B64(normalizeClaim(code));
  const exp = Date.now() + ttlSeconds * 1000;
  await env.VAULT.put(claimKey(hash), JSON.stringify({ space, exp }), { expirationTtl: ttlSeconds });
  return code;
}

// Validate a code and CONSUME it (one-time). Returns { space } on success, null otherwise.
// Deletes the record on success and on expiry, so a code never works twice and dead codes get swept.
export async function verifyAndConsumeClaim(env, code, now = Date.now()) {
  const normalized = normalizeClaim(code);
  if (!normalized) return null;
  const hash = await sha256B64(normalized);
  const raw = await env.VAULT.get(claimKey(hash));
  if (!raw) return null;
  let rec;
  try { rec = JSON.parse(raw); } catch { await env.VAULT.delete(claimKey(hash)); return null; }
  if (!rec || !rec.space || typeof rec.exp !== "number" || rec.exp < now) {
    await env.VAULT.delete(claimKey(hash));
    return null;
  }
  await env.VAULT.delete(claimKey(hash)); // consume — one-time
  return { space: rec.space };
}
