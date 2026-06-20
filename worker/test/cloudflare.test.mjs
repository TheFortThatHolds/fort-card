// Connect Cloudflare OAuth + provisioning helpers — PKCE, discovery, authorize URL, token exchange,
// and the Cloudflare API calls (against a mock fetch). Run: node test/cloudflare.test.mjs
import {
  generatePkce, discover, DEFAULT_AUTHORIZE_URL, DEFAULT_TOKEN_URL, DEFAULT_SCOPES, buildAuthorizeUrl, exchangeCode,
  firstAccountId, createKvNamespace, uploadLockbox, enableWorkersDev, fetchLockboxSource,
} from "../src/cloudflare.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));
const okThrow = async (fn, m) => { try { await fn(); ok(false, m); } catch { ok(true, m); } };

// minimal mock fetch keyed by URL substring → { status, json|text }
function mockFetch(routes) {
  const calls = [];
  const f = async (url, init = {}) => {
    calls.push({ url, init });
    for (const [frag, resp] of routes) {
      if (url.includes(frag)) {
        const r = typeof resp === "function" ? resp(url, init) : resp;
        return {
          ok: (r.status || 200) < 400, status: r.status || 200,
          async json() { if (r.json === undefined) throw new Error("no json"); return r.json; },
          async text() { return r.text ?? ""; },
        };
      }
    }
    return { ok: false, status: 404, async json() { return {}; }, async text() { return ""; } };
  };
  f.calls = calls;
  return f;
}

(async () => {
  // 1. PKCE: verifier + S256 challenge, url-safe, distinct
  {
    const { verifier, challenge } = await generatePkce();
    ok(/^[A-Za-z0-9_-]+$/.test(verifier) && verifier.length >= 43, "verifier is url-safe high-entropy");
    ok(/^[A-Za-z0-9_-]+$/.test(challenge) && challenge !== verifier, "challenge is the S256 of verifier, url-safe");
  }

  // 2. fixed Cloudflare endpoints (no network), env-overridable
  {
    const d = await discover({});
    ok(d.authorization_endpoint === DEFAULT_AUTHORIZE_URL && d.token_endpoint === DEFAULT_TOKEN_URL, "discover returns the fixed Cloudflare endpoints");
    const d2 = await discover({ CF_OAUTH_AUTHORIZE_URL: "https://x/a", CF_OAUTH_TOKEN_URL: "https://x/t" });
    ok(d2.authorization_endpoint === "https://x/a" && d2.token_endpoint === "https://x/t", "env overrides the endpoints");
  }

  // 3. authorize URL carries PKCE + code response type; omits empty scope
  {
    const u = new URL(buildAuthorizeUrl({ authorization_endpoint: "https://cf/auth", clientId: "cid", redirectUri: "https://card/cb", scope: "", state: "st", challenge: "ch" }));
    ok(u.searchParams.get("response_type") === "code", "response_type=code");
    ok(u.searchParams.get("client_id") === "cid", "client_id set");
    ok(u.searchParams.get("code_challenge") === "ch" && u.searchParams.get("code_challenge_method") === "S256", "PKCE challenge + S256");
    ok(u.searchParams.get("state") === "st", "state set");
    ok(!u.searchParams.has("scope"), "empty scope omitted (uses registered scopes)");
    const us = new URL(buildAuthorizeUrl({ authorization_endpoint: "https://cf/auth", clientId: "cid", redirectUri: "https://card/cb", scope: DEFAULT_SCOPES, state: "st", challenge: "ch" }));
    ok(us.searchParams.get("scope") === DEFAULT_SCOPES, "default scopes are carried when provided");
  }

  // 3b. DEFAULT_SCOPES covers the provisioning calls the callback makes (account + workers + kv)
  {
    ok(/account-settings\.read/.test(DEFAULT_SCOPES), "default scopes include account-settings.read (self-managed-client format)");
    ok(/workers-scripts\.write/.test(DEFAULT_SCOPES) && /workers-kv-storage\.write/.test(DEFAULT_SCOPES), "default scopes include workers-scripts.write + workers-kv-storage.write");
    ok(!/[:_]/.test(DEFAULT_SCOPES.replace(/\s/g, "")), "scopes use dash/dot form, not wrangler's underscore/colon form");
  }

  // 4. token exchange sends code_verifier, no client_secret; surfaces failures
  {
    const f = mockFetch([["/token", (url, init) => {
      const body = init.body.toString();
      ok(body.includes("code_verifier=ver") && body.includes("grant_type=authorization_code"), "exchange posts verifier + grant_type");
      ok(!body.includes("client_secret"), "exchange sends NO client_secret (PKCE)");
      return { json: { access_token: "AT", token_type: "bearer" } };
    }]]);
    const t = await exchangeCode({ token_endpoint: "https://cf/token", clientId: "cid", redirectUri: "https://card/cb", code: "c", verifier: "ver" }, f);
    ok(t.access_token === "AT", "returns access_token");
    await okThrow(() => exchangeCode({ token_endpoint: "https://cf/token", clientId: "cid", redirectUri: "x", code: "c", verifier: "v" }, mockFetch([["/token", { status: 400, json: { error: "bad" } }]])), "exchange throws on error response");
  }

  // 5. account id from /accounts
  {
    const f = mockFetch([["/accounts", { json: { success: true, result: [{ id: "acct123" }] } }]]);
    ok((await firstAccountId("AT", f)) === "acct123", "firstAccountId picks the granted account");
    await okThrow(() => firstAccountId("AT", mockFetch([["/accounts", { json: { success: true, result: [] } }]])), "throws when no account");
  }

  // 6. create KV returns the namespace id (none existing → create)
  {
    const f = mockFetch([["/storage/kv/namespaces", (url, init) => init.method === "POST"
      ? { json: { success: true, result: { id: "kv789" } } }
      : { json: { success: true, result: [] } }]]);
    ok((await createKvNamespace("AT", "acct", "fort-card-lockbox", f)) === "kv789", "createKvNamespace creates + returns id when none exists");
  }

  // 6b. idempotent retry: a namespace with this title already exists → reuse it, no POST
  {
    const f = mockFetch([["/storage/kv/namespaces", (url, init) => init.method === "POST"
      ? { json: { success: true, result: { id: "kvNEW" } } }
      : { json: { success: true, result: [{ id: "other", title: "something-else" }, { id: "kvExisting", title: "fort-card-lockbox" }] } }]]);
    ok((await createKvNamespace("AT", "acct", "fort-card-lockbox", f)) === "kvExisting", "createKvNamespace reuses the existing namespace by title");
    ok(!f.calls.some((c) => c.init.method === "POST"), "no POST when the namespace already exists (retry-safe)");
  }

  // 7. upload binds KV as LM and uploads worker.js as a module
  {
    let seen;
    const f = mockFetch([["/workers/scripts/", (url, init) => { seen = init; return { json: { success: true, result: {} } }; }]]);
    await uploadLockbox("AT", "acct", "fort-card-lockbox", "export default {}", "kv789", f);
    ok(seen.method === "PUT" && seen.body instanceof FormData, "upload is a PUT multipart");
    const meta = JSON.parse(await seen.body.get("metadata").text());
    ok(meta.main_module === "worker.js", "metadata main_module=worker.js");
    ok(meta.bindings.some((b) => b.type === "kv_namespace" && b.name === "LM" && b.namespace_id === "kv789"), "binds KV namespace as LM");
  }

  // 8. enable workers.dev computes the public url from the subdomain
  {
    const f = mockFetch([
      ["/subdomain", (url) => url.includes("/workers/subdomain") ? { json: { success: true, result: { subdomain: "jimmy" } } } : { json: { success: true, result: {} } }],
    ]);
    ok((await enableWorkersDev("AT", "acct", "fort-card-lockbox", f)) === "https://fort-card-lockbox.jimmy.workers.dev", "builds workers.dev url");
  }

  // 8b. fresh account has NO workers.dev subdomain → we create one, then build the url from it
  {
    const f = mockFetch([
      ["/workers/subdomain", (url, init) => init.method === "PUT"
        ? { json: { success: true, result: { subdomain: "fcnewacct" } } }   // create succeeds
        : { json: { success: true, result: { subdomain: null } } }],         // none yet on GET
      ["/subdomain", { json: { success: true, result: {} } }],               // script route enable
    ]);
    const url = await enableWorkersDev("AT", "acct", "fort-card-lockbox", f);
    ok(url === "https://fort-card-lockbox.fcnewacct.workers.dev", "creates a subdomain on a fresh account, then builds the url");
    ok(f.calls.some((c) => c.url.includes("/workers/subdomain") && c.init.method === "PUT"), "PUT creates the account workers.dev subdomain");
  }

  // 9. lockbox source must look like a module
  {
    ok((await fetchLockboxSource({}, mockFetch([["raw.githubusercontent", { text: "export default { async fetch(){} }" }]]))).includes("export default"), "fetches valid source");
    await okThrow(() => fetchLockboxSource({}, mockFetch([["raw.githubusercontent", { text: "not a worker" }]])), "throws on bogus source");
  }

  console.log(`\ncloudflare: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
