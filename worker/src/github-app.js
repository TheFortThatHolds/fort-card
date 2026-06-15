// Fort Card — GITHUB APP auth for the wake-back. The wallet posts the "approved, go" comment to a
// requesting agent's PR using the ONE Fort Wallet GitHub App's INSTALLATION token: scoped to only
// the repos the owner installed the app on, minted on the fly from the app's private key. No
// operator PAT, no per-customer app — one app, installed per repo, writes only where consented.
//
// Secrets (Worker): GH_APP_ID (the app id, e.g. a number) and GH_APP_PRIVATE_KEY (the app's .pem).
// Both live in the wallet's secrets, never the repo. Unset = no auto-wake (the push still notifies).

const enc = new TextEncoder();
const b64url = (b) => { const u = b instanceof Uint8Array ? b : new Uint8Array(b); let s = ""; for (const x of u) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const b64ToBytes = (s) => { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };

// DER length + PKCS#1 → PKCS#8 wrap. GitHub app keys are PEM PKCS#1 ("BEGIN RSA PRIVATE KEY");
// WebCrypto only imports PKCS#8, so wrap it. A "BEGIN PRIVATE KEY" pem is already PKCS#8.
function derLen(n) { if (n < 128) return [n]; const out = []; let x = n; while (x > 0) { out.unshift(x & 0xff); x >>= 8; } return [0x80 | out.length, ...out]; }
function pemToPkcs8(pem) {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = b64ToBytes(body);
  if (pem.includes("BEGIN PRIVATE KEY")) return der; // already PKCS#8
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const version = [0x02, 0x01, 0x00];
  const octet = [0x04, ...derLen(der.length), ...Array.from(der)];
  const inner = [...version, ...algId, ...octet];
  return new Uint8Array([0x30, ...derLen(inner.length), ...inner]);
}

// App JWT (RS256), iss = app id, ~9 min lifetime, iat backdated 60s for clock skew.
export async function mintAppJwt(env) {
  const key = await crypto.subtle.importKey("pkcs8", pemToPkcs8(env.GH_APP_PRIVATE_KEY), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = b64url(enc.encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(env.GH_APP_ID) })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, enc.encode(header + "." + payload)));
  return header + "." + payload + "." + b64url(sig);
}

const GH = { "User-Agent": "fort-card", Accept: "application/vnd.github+json" };

// Mint a short-lived installation token for the repo (only works if the owner installed the app there).
async function installationToken(env, owner, repo, jwt) {
  const inst = await fetch(`https://api.github.com/repos/${owner}/${repo}/installation`, { headers: { ...GH, Authorization: "Bearer " + jwt } });
  if (!inst.ok) throw new Error("no installation on " + owner + "/" + repo + " (" + inst.status + ")");
  const id = (await inst.json()).id;
  const tok = await fetch(`https://api.github.com/app/installations/${id}/access_tokens`, { method: "POST", headers: { ...GH, Authorization: "Bearer " + jwt } });
  if (!tok.ok) throw new Error("installation token failed (" + tok.status + ")");
  return (await tok.json()).token;
}

export function appConfigured(env) {
  return !!(env.GH_APP_ID && env.GH_APP_PRIVATE_KEY);
}

// Resolve the owner of the repo's installation → their space (github:<account id>). This is how a
// request names its space WITHOUT a wallet credential: the app is installed on the repo by its
// owner, so the installation tells us (verifiably) whose space it is. Throws if not installed.
export async function getInstallationOwner(env, repoFull) {
  const [owner, repo] = String(repoFull).split("/");
  if (!owner || !repo) throw new Error("repo must be owner/name");
  const jwt = await mintAppJwt(env);
  const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/installation`, { headers: { ...GH, Authorization: "Bearer " + jwt } });
  if (!r.ok) throw new Error("Fort Wallet is not installed on " + repoFull + " (" + r.status + ")");
  const inst = await r.json();
  return { id: inst.account && inst.account.id, login: inst.account && inst.account.login };
}

// Post a comment to owner/repo issue|PR #num via the app installation. Returns true on success.
export async function postComment(env, repoFull, num, bodyText) {
  if (!appConfigured(env)) return false;
  const [owner, repo] = String(repoFull).split("/");
  if (!owner || !repo) return false;
  const jwt = await mintAppJwt(env);
  const token = await installationToken(env, owner, repo, jwt);
  const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues/${num}/comments`, {
    method: "POST",
    headers: { ...GH, Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ body: bodyText }),
  });
  return r.ok;
}
