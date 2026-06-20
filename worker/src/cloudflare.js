// Connect Cloudflare — the one-tap onboarding. Instead of the customer deploying the lockbox and
// telling us its URL (claim-code / paste-URL), the WALLET deploys it FOR them: the customer taps
// "Connect Cloudflare" once, approves on Cloudflare's consent screen, and we create the KV +
// upload the lockbox worker into THEIR account via Cloudflare's API. Zero typing, zero paste —
// because the wallet was on both ends, there's nothing for the customer to carry back.
//
// Auth: OAuth 2.0 Authorization Code + PKCE (public client — NO client secret exists; the security
// is the one-time code challenge). The client id is non-secret. Endpoints are discovered at runtime
// (RFC 8414) so we never hardcode Cloudflare's authorize/token URLs.
//
// DOCTRINE: the only operator secret this could need (there is none, thanks to PKCE) would live as
// a Worker Secret on this worker — never in the repo, never a card. Customer keys stay sovereign:
// the lockbox self-mints its MASTER_KEY on its first boot inside the customer's account; we only
// ever learn the relay token (via the lockbox's own /bootstrap), never the KEK.

const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// ── PKCE ──
export async function generatePkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
  return { verifier, challenge };
}

// ── RFC 8414 discovery: read authorize + token endpoints from Cloudflare's metadata doc, so the
// exact URLs are never hardcoded (Cloudflare buries them; this is the correct way regardless). ──
// Cloudflare's OAuth endpoints are FIXED (the same ones `wrangler login` uses) — there is no
// RFC-8414 discovery doc to fetch (the .well-known URL returns the dashboard HTML, not JSON, which
// is what crashed the connect flow). So we use the known endpoints directly, env-overridable in
// case Cloudflare ever changes them. No network call = no parse-failure point.
export const DEFAULT_AUTHORIZE_URL = "https://dash.cloudflare.com/oauth2/auth";
export const DEFAULT_TOKEN_URL = "https://dash.cloudflare.com/oauth2/token";

// Cloudflare's consent form needs the exact scopes being granted, and they must MATCH the strings
// registered on the self-managed OAuth client (a stray/misnamed scope → `invalid_scope`). NOTE the
// format: self-managed OAuth clients use dash-and-dot scope ids (`workers-scripts.write`), NOT the
// underscore-and-colon form wrangler's first-party client uses (`workers_scripts:write`). These are
// the exact three the client registered, copied from its scope panel — the tight set provisioning
// needs: account-settings.read to find the account, workers-kv-storage.write to create the KV,
// workers-scripts.write to upload the lockbox + flip on its workers.dev route. NO offline_access —
// that's an OIDC refresh concept, not a Cloudflare scope, and one-shot provisioning never refreshes.
// Env-overridable (CF_OAUTH_SCOPES) so an instance can match whatever its client registered.
export const DEFAULT_SCOPES =
  "account-settings.read workers-kv-storage.write workers-scripts.write";
export async function discover(env) {
  return {
    authorization_endpoint: env.CF_OAUTH_AUTHORIZE_URL || DEFAULT_AUTHORIZE_URL,
    token_endpoint: env.CF_OAUTH_TOKEN_URL || DEFAULT_TOKEN_URL,
  };
}

// Build the consent URL we send the owner to.
export function buildAuthorizeUrl({ authorization_endpoint, clientId, redirectUri, scope, state, challenge }) {
  const u = new URL(authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", redirectUri);
  if (scope) u.searchParams.set("scope", scope); // omitted → Cloudflare uses the client's registered scopes
  u.searchParams.set("state", state);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

// Exchange the authorization code for an access token (PKCE — no client secret).
export async function exchangeCode({ token_endpoint, clientId, redirectUri, code, verifier }, fetchImpl = fetch) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: verifier,
  });
  const r = await fetchImpl(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error("token exchange failed (" + r.status + (j.error ? ": " + j.error : "") + ")");
  return j; // { access_token, token_type, expires_in?, refresh_token? }
}

// ── Cloudflare API (with the user's OAuth access token) ──
const API = "https://api.cloudflare.com/client/v4";
async function cfApi(token, path, init = {}, fetchImpl = fetch) {
  const r = await fetchImpl(API + path, {
    ...init,
    headers: { Authorization: "Bearer " + token, ...(init.headers || {}) },
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) {
    const msg = (j.errors && j.errors[0] && j.errors[0].message) || ("HTTP " + r.status);
    throw new Error("cloudflare api " + path + " failed: " + msg);
  }
  return j.result;
}

// The account the OAuth grant covers (the user picked it on the consent screen).
export async function firstAccountId(token, fetchImpl = fetch) {
  const accounts = await cfApi(token, "/accounts", {}, fetchImpl);
  if (!Array.isArray(accounts) || !accounts.length) throw new Error("no Cloudflare account on this grant");
  return accounts[0].id;
}

export async function createKvNamespace(token, accountId, title, fetchImpl = fetch) {
  const res = await cfApi(token, "/accounts/" + accountId + "/storage/kv/namespaces", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title }),
  }, fetchImpl);
  return res.id;
}

// Upload the lockbox as an ES-module Worker, binding the KV namespace as `LM` (what the lockbox
// reads). The script self-mints its keys on first boot — we set no secrets here.
export async function uploadLockbox(token, accountId, scriptName, source, kvNamespaceId, fetchImpl = fetch) {
  const metadata = {
    main_module: "worker.js",
    compatibility_date: "2026-06-01",
    bindings: [{ type: "kv_namespace", name: "LM", namespace_id: kvNamespaceId }],
  };
  const form = new FormData();
  form.set("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
  form.set("worker.js", new Blob([source], { type: "application/javascript+module" }), "worker.js");
  await cfApi(token, "/accounts/" + accountId + "/workers/scripts/" + scriptName, { method: "PUT", body: form }, fetchImpl);
}

// A brand-new Cloudflare account has NO account-level workers.dev subdomain until the owner first
// opens Workers & Pages in the dashboard — so enabling the script's route dead-ends for exactly the
// new customers this one-tap is built for ("You do not have a workers.dev subdomain"). Our OAuth
// grant carries workers-scripts.write, which also covers the account subdomain, so create one
// ourselves. The name is just plumbing (the lockbox URL is internal), so derive a likely-unique
// one from the account id and fall back to a randomized variant on the rare global collision.
export async function ensureAccountSubdomain(token, accountId, fetchImpl = fetch) {
  const existing = await cfApi(token, "/accounts/" + accountId + "/workers/subdomain", {}, fetchImpl).catch(() => null);
  if (existing && existing.subdomain) return existing.subdomain;
  const base = "fc" + String(accountId).toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 18);
  let lastErr;
  for (let i = 0; i < 4; i++) {
    const name = i === 0 ? base : base.slice(0, 14) + Math.random().toString(36).slice(2, 8);
    try {
      const res = await cfApi(token, "/accounts/" + accountId + "/workers/subdomain", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subdomain: name }),
      }, fetchImpl);
      return (res && res.subdomain) || name;
    } catch (e) {
      lastErr = e; // taken / invalid → try a randomized variant
    }
  }
  throw new Error("could not create a workers.dev subdomain: " + ((lastErr && lastErr.message) || "failed"));
}

// Turn on the script's workers.dev route and compute its public URL.
export async function enableWorkersDev(token, accountId, scriptName, fetchImpl = fetch) {
  // Make sure the account actually has a workers.dev subdomain first (fresh accounts don't), or the
  // enable call below fails for every brand-new customer.
  const subdomain = await ensureAccountSubdomain(token, accountId, fetchImpl);
  await cfApi(token, "/accounts/" + accountId + "/workers/scripts/" + scriptName + "/subdomain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: true }),
  }, fetchImpl);
  return "https://" + scriptName + "." + subdomain + ".workers.dev";
}

// Fetch the canonical lockbox source from the published public repo (single source of truth).
export const DEFAULT_LOCKBOX_SRC = "https://raw.githubusercontent.com/TheFortThatHolds/fort-card-lockbox/main/src/worker.js";
export async function fetchLockboxSource(env, fetchImpl = fetch) {
  const url = env.LOCKBOX_SRC_URL || DEFAULT_LOCKBOX_SRC;
  const r = await fetchImpl(url);
  if (!r.ok) throw new Error("could not fetch lockbox source (" + r.status + ")");
  const src = await r.text();
  if (!/export\s+default/.test(src)) throw new Error("fetched lockbox source looks wrong");
  return src;
}
