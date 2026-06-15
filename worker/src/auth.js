// Fort Card — IDENTITY. GitHub-App login that BIRTHS A SPACE from a verified identity.
//
// This is what turns the wallet from "single-token self-host" into a multi-tenant SaaS:
// a stranger signs in with GitHub, and a sealed space is called into being from their
// IMMUTABLE numeric id (`github:<id>`) — never their username/email (mutable → takeover).
// Nothing is addressable before a verified login; the space does not exist until identity
// proves it into existence (kills space-squatting + enumeration).
//
// What this module is NOT: it is not the sensitive-action gate. Per DESIGN §3/§4, issuing /
// approving / rotating / revealing still demand a fresh passkey tap (built next). This layer
// only answers "who is this, and which space are they in." The session it mints is a thin,
// short-lived identity cookie — there is no long-lived powerful session to steal, because the
// session alone can do nothing sensitive without the per-action passkey ceremony on top.
//
// Hardening (DESIGN §2): `state` param (CSRF / code-injection), exact callback-URI from config,
// validate the identity server-side, use the immutable id, NEVER link accounts by email.
//
// Routes (added to the worker):
//   GET /login            → 302 to GitHub authorize (sets a signed, short-lived `state` cookie)
//   GET /callback         → verify state, exchange code, read immutable id, mint session, → /app
//   GET /logout           → clear the session cookie
//   GET /whoami           → { login, space } for the current session, or 401
//
// Config (Worker vars/secrets — set by the operator of a managed instance; a pure self-host
// that only uses FORT_KEY can leave these unset and OAuth simply stays off):
//   GH_CLIENT_ID       the Fort Wallet GitHub App's client id
//   GH_CLIENT_SECRET   its client secret
//   GH_CALLBACK_URL    the EXACT callback url registered on the App (allowlist; no guessing)
//   secret SESSION_SECRET   (optional) HMAC key for signing cookies; self-mints into VAULT if unset

const enc = new TextEncoder();
export const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const b64ud = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(s + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
};

export function oauthConfigured(env) {
  return !!(env.GH_CLIENT_ID && env.GH_CLIENT_SECRET && env.GH_CALLBACK_URL);
}

// ── the cookie signing key. A Worker secret wins (bring-your-own); else self-mint one into the
// VAULT KV and reuse it forever — the operator never types a session key, same posture as the
// last-mile worker's self-minting root. Constant per deployment, so cookies verify across requests.
async function signingKey(env) {
  let raw = env.SESSION_SECRET;
  if (!raw) {
    if (!env.VAULT) throw new Error("no SESSION_SECRET and no VAULT KV to mint one into");
    raw = await env.VAULT.get("_session:hmac");
    if (!raw) {
      raw = b64u(crypto.getRandomValues(new Uint8Array(32)).buffer);
      await env.VAULT.put("_session:hmac", raw);
    }
  }
  return crypto.subtle.importKey("raw", enc.encode(raw), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

// A token is `<payload-b64url>.<hmac-b64url>`. Payload is JSON {space, login, exp}. Tamper-proof
// (HMAC) and self-expiring (exp checked on verify), so it needs no server-side session store.
// Exported so other modules (passkey step-up, action tokens) sign/verify under the same key.
export async function sign(env, payload) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const mac = await crypto.subtle.sign("HMAC", await signingKey(env), enc.encode(body));
  return body + "." + b64u(mac);
}
export async function verify(env, token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, macPart] = token.split(".");
  const ok = await crypto.subtle.verify("HMAC", await signingKey(env), b64ud(macPart), enc.encode(body)).catch(() => false);
  if (!ok) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64ud(body))); } catch { return null; }
  if (!payload || (payload.exp && Date.now() > payload.exp)) return null;
  return payload;
}

export function readCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}
export function setCookie(name, value, maxAgeSec) {
  // Host-only, Secure, HttpOnly, SameSite=Lax (Lax so the GitHub redirect back carries the state
  // cookie). maxAge 0 clears it.
  const bits = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  bits.push(maxAgeSec > 0 ? `Max-Age=${maxAgeSec}` : "Max-Age=0");
  return bits.join("; ");
}
const redirect = (location, headers = {}) => new Response(null, { status: 302, headers: { Location: location, ...headers } });
const jsonResp = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });

const SESSION_COOKIE = "fc_session";
const STATE_COOKIE = "fc_oauth_state";
const SESSION_TTL_SEC = 60 * 60 * 8; // 8h identity cookie; sensitive acts still need a passkey tap
const STATE_TTL_SEC = 60 * 10; // 10 min to complete the round-trip

// ── resolve the current human session → { space, login } or null. Called on every request so
// the worker knows which tenant's space to operate in. Returns null for bearer/agent callers and
// anonymous requests; those are handled by the existing token path. ──
export async function resolveSession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  return token ? verify(env, token) : null;
}

// ── the OAuth routes. Returns a Response if it handled the path, else null (let the worker route
// it). Kept here so worker.js stays the card logic and this stays identity. ──
export async function handleAuth(request, env, url, path) {
  if (!oauthConfigured(env)) return null; // OAuth off (pure self-host) — these routes don't exist

  // GET /login → bounce to GitHub with an unguessable, signed, short-lived state.
  if (path === "/login" && request.method === "GET") {
    const state = b64u(crypto.getRandomValues(new Uint8Array(16)).buffer);
    const stateTok = await sign(env, { state, exp: Date.now() + STATE_TTL_SEC * 1000 });
    const authorize = new URL("https://github.com/login/oauth/authorize");
    authorize.searchParams.set("client_id", env.GH_CLIENT_ID);
    authorize.searchParams.set("redirect_uri", env.GH_CALLBACK_URL); // EXACT — GitHub allowlists it too
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("scope", ""); // identity only — no repo permissions to authenticate
    authorize.searchParams.set("allow_signup", "true");
    return redirect(authorize.toString(), { "Set-Cookie": setCookie(STATE_COOKIE, stateTok, STATE_TTL_SEC) });
  }

  // GET /callback → verify state (CSRF), exchange code, read the IMMUTABLE id, birth the space.
  if (path === "/callback" && request.method === "GET") {
    const code = url.searchParams.get("code");
    const returnedState = url.searchParams.get("state");
    const stateTok = readCookie(request, STATE_COOKIE);
    const stateClaim = await verify(env, stateTok);
    // The state must (a) verify as ours, (b) be unexpired, (c) match what GitHub echoed back.
    if (!code || !stateClaim || !returnedState || stateClaim.state !== returnedState) {
      return jsonResp({ error: "invalid or expired login state — start again at /login" }, 400);
    }

    // Exchange the code for a token, server-to-server (the secret never touches the browser).
    const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: env.GH_CLIENT_ID,
        client_secret: env.GH_CLIENT_SECRET,
        code,
        redirect_uri: env.GH_CALLBACK_URL,
      }),
    });
    const tokenData = await tokenResp.json().catch(() => ({}));
    const accessToken = tokenData && tokenData.access_token;
    if (!accessToken) return jsonResp({ error: "GitHub token exchange failed" }, 401);

    // Validate the identity server-side and take the IMMUTABLE numeric id. Username/email are
    // mutable (rename / re-claim = account takeover), so they NEVER form the space id.
    const userResp = await fetch("https://api.github.com/user", {
      headers: { Authorization: "Bearer " + accessToken, "User-Agent": "fort-card", Accept: "application/vnd.github+json" },
    });
    const ghUser = await userResp.json().catch(() => ({}));
    if (!userResp.ok || !ghUser || typeof ghUser.id !== "number") {
      return jsonResp({ error: "could not verify GitHub identity" }, 401);
    }

    const space = "github:" + ghUser.id; // server-derived, immutable — never from a client header
    const session = await sign(env, { space, login: ghUser.login || null, exp: Date.now() + SESSION_TTL_SEC * 1000 });
    // Land in the wallet PWA; clear the one-shot state cookie.
    const headers = new Headers();
    headers.append("Set-Cookie", setCookie(SESSION_COOKIE, session, SESSION_TTL_SEC));
    headers.append("Set-Cookie", setCookie(STATE_COOKIE, "", 0));
    headers.set("Location", "/app");
    return new Response(null, { status: 302, headers });
  }

  // GET /logout → drop the identity cookie. (Nothing server-side to revoke — it's stateless.)
  if (path === "/logout" && request.method === "GET") {
    return redirect("/", { "Set-Cookie": setCookie(SESSION_COOKIE, "", 0) });
  }

  // GET /whoami → who's logged in + which space, for the PWA to render.
  if (path === "/whoami" && request.method === "GET") {
    const s = await resolveSession(request, env);
    return s ? jsonResp({ login: s.login, space: s.space }) : jsonResp({ error: "not signed in" }, 401);
  }

  return null;
}
