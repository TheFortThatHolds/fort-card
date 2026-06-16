// Fort Card — CONNECT: the agent's front door.
//
// An MCP server + OAuth 2.1 sign-in so an off-the-shelf agent (Claude Code / Codex / any MCP
// client) connects to THIS wallet by URL — and the OWNER approves the connection with their
// real GitHub + passkey sign-in, NEVER a pasted key. On approval the agent gets a scoped,
// revocable pass tied to that one connection. The pass can:
//   • see   — list the cards in the space (names/limits only, never a key value)
//   • use   — charge a card the owner already approved (chargeCard enforces every fence)
//   • ask   — request a NEW card or a recharge → lands PENDING → pushes the owner's phone
// It can NEVER issue/approve/recharge on its own. "Issuing" is ask-then-the-owner-approves.
//
// This door is the SAME one the owner uses as customer #1 — there is no operator backdoor and
// no Memory-Core coupling. Ported from the Core's proven MCP+OAuth pattern (mcp.ts + oauth.ts),
// adapted so the consent step is the wallet's GitHub+passkey login instead of a pasted key.
//
// Reuses from worker.js (exported there): K, chargeCard, logEvent, notifyCardRequest, stepIfSession.
// Reuses from auth.js: sign, verify, resolveSession, oauthConfigured.

import { resolveSession, oauthConfigured, verify, readCookie } from "./auth.js";
import { K, chargeCard, logEvent, notifyCardRequest, spaceSubscribed } from "./worker.js";

const CODE_TTL = 600;                 // auth code: 10 min
const TOKEN_TTL = 60 * 60 * 24 * 30;  // agent pass: 30 days
const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = { name: "fort-card", version: "0.1.0" };

const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });
const htmlResp = (body, status = 200) =>
  new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8" } });

function originOf(env, url) {
  return env.WALLET_ORIGIN || (url.protocol + "//" + url.host);
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function rand() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256b64url(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return btoa(String.fromCharCode(...new Uint8Array(d))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── OAuth discovery metadata (what an MCP client fetches to learn how to connect) ──
function authServerMetadata(origin) {
  return {
    issuer: origin,
    authorization_endpoint: origin + "/authorize",
    token_endpoint: origin + "/token",
    registration_endpoint: origin + "/register",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["wallet.agent"],
  };
}
function protectedResourceMetadata(origin) {
  return { resource: origin + "/mcp", authorization_servers: [origin] };
}

// ── the agent pass: a token in KV → { space, login, scope:"agent", client }, revocable ──
async function mintAgentPass(env, principal) {
  const access = "fca_" + rand();
  const refresh = "fcr_" + rand();
  const val = JSON.stringify(principal);
  await env.VAULT.put(K(principal.space, "agentpass", access), val, { expirationTtl: TOKEN_TTL });
  await env.VAULT.put(K(principal.space, "agentrefresh", refresh), val, { expirationTtl: TOKEN_TTL * 6 });
  // also index by raw token so /mcp can resolve without knowing the space up front
  await env.VAULT.put("agentpass:" + access, val, { expirationTtl: TOKEN_TTL });
  await env.VAULT.put("agentrefresh:" + refresh, val, { expirationTtl: TOKEN_TTL * 6 });
  return { access, refresh };
}
async function resolveAgentPass(env, token) {
  if (!token || !token.startsWith("fca_")) return null;
  return await env.VAULT.get("agentpass:" + token, "json");
}

// ── the connect-door router. Returns a Response if it handled the path, else null. ──
export async function handleConnect(request, env, url, path) {
  if (!oauthConfigured(env)) return null; // no GitHub login configured = no agent door
  const origin = originOf(env, url);

  // Discovery — MCP clients hit these first to learn the flow.
  if (path === "/.well-known/oauth-authorization-server" && request.method === "GET")
    return json(authServerMetadata(origin));
  if (path === "/.well-known/oauth-protected-resource" && request.method === "GET")
    return json(protectedResourceMetadata(origin));

  // Dynamic Client Registration — the MCP client registers itself (RFC 7591).
  if (path === "/register" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const client_id = "fcc-" + crypto.randomUUID();
    const rec = {
      client_id,
      redirect_uris: Array.isArray(body.redirect_uris) ? body.redirect_uris : [],
      client_name: body.client_name || "MCP Client",
      token_endpoint_auth_method: "none",
    };
    await env.VAULT.put("oauthclient:" + client_id, JSON.stringify(rec));
    return json({ ...rec, grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }, 201);
  }

  // GET /authorize — the consent. Requires the owner be SIGNED IN (GitHub session); if not,
  // bounce to /login and come straight back here. When signed in, show the Allow screen.
  if (path === "/authorize" && request.method === "GET") {
    const session = await resolveSession(request, env);
    if (!session) {
      // hand /login a SAME-ORIGIN PATH to return to (it rejects anything not starting with "/").
      const back = url.pathname + url.search;
      return Response.redirect(origin + "/login?return=" + encodeURIComponent(back), 302);
    }
    // Hosted-billing gate: connecting an agent is a paid feature on the managed instance. Self-host
    // (no billing card) passes through. Don't make them do the passkey only to be rejected — stop here.
    if (!(await spaceSubscribed(env, session.space)))
      return htmlResp(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Subscribe to connect</title><body style="margin:0;font:16px -apple-system,system-ui,sans-serif;background:#14110e;color:#efe7da;padding:24px"><div style="max-width:440px;margin:24px auto;background:#1a1610;border:1px solid #2c2620;border-radius:14px;padding:22px"><h1 style="font-size:19px">Subscribe to connect an agent</h1><p style="color:#9a8f7d;line-height:1.5">Connecting an agent to your wallet needs an active Fort Card subscription. <a href="/app" style="color:#b87333">Open your wallet</a> to subscribe, then try connecting again.</p></div></body>`, 402);
    const p = url.searchParams;
    const client = await env.VAULT.get("oauthclient:" + (p.get("client_id") || ""), "json");
    const clientName = client ? esc(client.client_name) : "An agent";
    const fields = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"]
      .map((k) => `<input type="hidden" name="${k}" value="${esc(p.get(k) || "")}">`).join("");
    return htmlResp(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect agent to your Fort Card</title>
<style>body{margin:0;font:16px -apple-system,system-ui,sans-serif;background:#14110e;color:#efe7da;padding:24px}
.card{max-width:440px;margin:24px auto;background:#1a1610;border:1px solid #2c2620;border-radius:14px;padding:22px}
h1{font-size:19px}.sub{color:#9a8f7d;font-size:14px;line-height:1.5}b{color:#efe7da}
button{width:100%;padding:14px;margin-top:16px;border:none;border-radius:10px;background:#b87333;color:#14110e;font-weight:600;font-size:16px}</style>
<div class="card">
<h1>🔌 Connect <b>${clientName}</b> to your wallet</h1>
<p class="sub">Signed in as <b>${esc(session.login || session.space)}</b>. Allowing this connection lets the agent
<b>see your cards</b>, <b>use cards you've approved</b>, and <b>ask</b> for new cards or recharges
(which buzz your phone to approve). It can <b>never</b> issue, recharge, or approve on its own.</p>
<form method="POST" action="/authorize" id="f">${fields}
<button type="button" id="allow">Approve with your passkey</button>
<p class="sub" id="msg"></p>
</form></div>
<script>
const s2b=s=>{s=s.split('-').join('+').split('_').join('/');return Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))};
const b2b=b=>btoa(String.fromCharCode(...new Uint8Array(b))).split('+').join('-').split('/').join('_').split('=').join('');
const jget=async(u,o)=>{const r=await fetch(u,o);if(!r.ok)throw new Error(((await r.json().catch(()=>({}))).error)||('HTTP '+r.status));return r.json()};
async function approve(){
  const m=document.getElementById('msg');
  try{
    m.textContent='Confirm on your device…';
    const {publicKey:o}=await jget('/passkey/assert/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'agent.connect'})});
    o.challenge=s2b(o.challenge);o.allowCredentials=(o.allowCredentials||[]).map(c=>({...c,id:s2b(c.id)}));
    const cred=await navigator.credentials.get({publicKey:o});
    await jget('/passkey/assert/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:cred.id,clientDataJSON:b2b(cred.response.clientDataJSON),authenticatorData:b2b(cred.response.authenticatorData),signature:b2b(cred.response.signature)})});
    document.getElementById('f').submit();
  }catch(e){m.innerHTML='<b style="color:#e7857a">'+(e.message||e.name||'cancelled')+'</b> — if your passkey is not set up yet, open your wallet, enable it, then try again.';}
}
document.getElementById('allow').onclick=approve;
</script>`);
  }

  // POST /authorize — the owner tapped Allow. Re-check the session, require a fresh passkey tap
  // (sensitive act, same as issuing), then mint a one-time code bound to the owner's space.
  if (path === "/authorize" && request.method === "POST") {
    const session = await resolveSession(request, env);
    if (!session) return json({ error: "sign in first" }, 401);
    const form = await request.formData();
    // Fresh passkey tap required — the same gate as issuing. The Allow page runs the wallet's EXISTING
    // passkey ceremony (reused, not rebuilt: /passkey/assert/begin → tap → /passkey/assert/finish),
    // which sets the fc_unlock cookie. We verify that cookie here. Each customer uses their OWN passkey.
    const unlock = await verify(env, readCookie(request, "fc_unlock"));
    if (!unlock || unlock.kind !== "unlock" || unlock.space !== session.space) {
      return json({ error: "unlock_required — approve with your passkey on the wallet page" }, 401);
    }
    if (!(await spaceSubscribed(env, session.space)))
      return json({ error: "subscribe_required — connecting an agent needs an active Fort Card subscription; subscribe in your wallet and try again" }, 402);
    const redirect_uri = String(form.get("redirect_uri") || "");
    if (!redirect_uri) return json({ error: "missing redirect_uri" }, 400);
    const code = rand();
    await env.VAULT.put("oauthcode:" + code, JSON.stringify({
      client_id: form.get("client_id"),
      redirect_uri,
      code_challenge: form.get("code_challenge") || "",
      principal: { space: session.space, login: session.login || null, scope: "agent" },
    }), { expirationTtl: CODE_TTL });
    const back = new URL(redirect_uri);
    back.searchParams.set("code", code);
    if (form.get("state")) back.searchParams.set("state", String(form.get("state")));
    return Response.redirect(back.toString(), 302);
  }

  // POST /token — exchange the code (verify PKCE) for an agent pass, or refresh one.
  if (path === "/token" && request.method === "POST") {
    const form = await request.formData();
    const grant = String(form.get("grant_type") || "");
    if (grant === "authorization_code") {
      const code = String(form.get("code") || "");
      const stored = await env.VAULT.get("oauthcode:" + code, "json");
      if (!stored) return json({ error: "invalid_grant" }, 400);
      await env.VAULT.delete("oauthcode:" + code);
      if (stored.code_challenge) {
        const got = await sha256b64url(String(form.get("code_verifier") || ""));
        if (got !== stored.code_challenge) return json({ error: "invalid_grant", error_description: "PKCE failed" }, 400);
      }
      const { access, refresh } = await mintAgentPass(env, stored.principal);
      return json({ access_token: access, token_type: "Bearer", expires_in: TOKEN_TTL, refresh_token: refresh, scope: "wallet.agent" });
    }
    if (grant === "refresh_token") {
      const rt = String(form.get("refresh_token") || "");
      const principal = await env.VAULT.get("agentrefresh:" + rt, "json");
      if (!principal) return json({ error: "invalid_grant" }, 400);
      const { access } = await mintAgentPass(env, principal);
      return json({ access_token: access, token_type: "Bearer", expires_in: TOKEN_TTL, scope: "wallet.agent" });
    }
    return json({ error: "unsupported_grant_type" }, 400);
  }

  // POST /mcp — the agent talks here, carrying its pass as a Bearer token.
  if (path === "/mcp" && request.method === "POST") {
    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const principal = await resolveAgentPass(env, token);
    if (!principal) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
        },
      });
    }
    if (!(await spaceSubscribed(env, principal.space)))
      return json({ error: "subscribe_required — this space's Fort Card subscription is inactive; renew it in your wallet" }, 402);
    return await handleMcp(request, env, principal);
  }

  return null;
}

// ── MCP JSON-RPC handler (ported from the Core's mcp.ts) ──
const TOOLS = [
  {
    name: "wallet_map",
    description: "ALWAYS CALL THIS FIRST when you need a credential. Returns the wallet MAP: usable_cards (approved cards you can spend right now, with their allowed hosts + remaining charges), requestable_secrets (keys stored in the wallet that have NO card yet — you can ask_card for one), and pending_cards (already requested, awaiting the owner). If what you need is a usable card -> use_card. If it's a requestable secret -> ask_card. If it's in NEITHER, the owner has not stored that key yet -> tell them which key to add to their wallet first.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "use_card",
    description: "Charge a card the owner already approved: the wallet injects the real key server-side and returns ONLY the upstream response. You never see the key.",
    inputSchema: {
      type: "object",
      required: ["card_id", "url"],
      properties: {
        card_id: { type: "string" },
        url: { type: "string", description: "must be on the card's allowed host" },
        method: { type: "string" },
        headers: { type: "object" },
        body: {},
      },
    },
  },
  {
    name: "ask_card",
    description: "ASK the owner for a NEW card (or recharge). Lands PENDING and buzzes the owner's phone to approve or deny — you cannot approve it yourself. REQUIRES a wake target (repo + pr): on approval the wallet posts a comment to that PR to RESUME you. If you're an interactive session with no PR yet, open one first to be your listening post, watch it, THEN ask.",
    inputSchema: {
      type: "object",
      required: ["name", "secret", "allowed_hosts", "repo", "pr"],
      properties: {
        name: { type: "string" },
        secret: { type: "string", description: "which stored secret the card points at" },
        allowed_hosts: { type: "array", items: { type: "string" } },
        limit: { type: "number", description: "charge cap; omit for owner to decide on approval" },
        repo: { type: "string", description: "owner/name — the repo whose PR the wallet wakes on approval" },
        pr: { type: "number", description: "the PR number to resume you through. No PR yet (interactive)? Open one first — it's your wake/listening post." },
      },
    },
  },
];

async function callTool(name, args, env, principal) {
  const space = principal.space;
  if (name === "wallet_map") {
    const list = await env.VAULT.list({ prefix: K(space, "card", "") });
    const usable_cards = [], pending_cards = [];
    for (const k of list.keys) {
      const c = JSON.parse(await env.VAULT.get(k.name));
      const view = {
        id: c.id, name: c.name, allowed_hosts: c.allowed_hosts,
        remaining: c.limit != null ? Math.max(0, c.limit - c.used) : null,
      };
      if (!c.pending && !c.frozen) usable_cards.push(view);
      else pending_cards.push({ ...view, state: c.pending ? "pending owner approval" : "frozen" });
    }
    // secrets stored in the wallet that have no card yet — the agent can ask_card for these
    const secPrefix = K(space, "secret", "");
    const secList = await env.VAULT.list({ prefix: secPrefix });
    const requestable_secrets = secList.keys.map((k) => k.name.slice(secPrefix.length));
    return {
      usable_cards,
      requestable_secrets,
      pending_cards,
      note: "Need a credential? (1) If a usable_card covers the host you need -> use_card. (2) Else if the key is in requestable_secrets -> ask_card (lands pending; the owner approves on their phone). (3) Else the owner has not stored that key -> tell them exactly which key to add to their wallet first; do NOT improvise or hold a raw key.",
    };
  }
  if (name === "use_card") {
    const c = await env.VAULT.get(K(space, "card", String(args.card_id)), "json");
    if (!c) return { error: "no such card — call wallet_map to see usable_cards, or ask_card if the key is a requestable_secret (or have the owner add it if it's neither)" };
    return await chargeCard(env, space, c, { url: args.url, method: args.method, headers: args.headers, body: args.body });
  }
  if (name === "ask_card") {
    if (!args.name || !args.secret || !Array.isArray(args.allowed_hosts) || !args.allowed_hosts.length)
      return { error: "name, secret, and a non-empty allowed_hosts are required" };
    if (!args.repo || !args.pr)
      return { error: "ask_card needs a wake target: repo + pr. On approval the wallet posts a wake-back comment to that PR to resume you. No PR yet (interactive session)? Open one first as your listening post, start watching it, then ask again." };
    const id = "card_" + crypto.randomUUID().slice(0, 8);
    const card = {
      id, name: String(args.name), secret: String(args.secret),
      holder: principal.login || null,
      allowed_hosts: args.allowed_hosts.map(String),
      header: "Authorization", header_prefix: "Bearer ",
      limit: typeof args.limit === "number" ? args.limit : null,
      used: 0, expires_at: null,
      frozen: true, pending: true, // inert until the owner approves on their phone
      wake: { repo: String(args.repo), pr: Number(args.pr) }, // on approval the wallet wakes you here
      created: new Date().toISOString(),
    };
    await env.VAULT.put(K(space, "card", id), JSON.stringify(card));
    await logEvent(env, space, "card.request", { id, name: card.name, secret: card.secret, allowed_hosts: card.allowed_hosts, limit: card.limit, wake: card.wake });
    await notifyCardRequest(env, space, card);
    return { ok: true, pending: true, card: id, note: "Asked — it's pending. The owner gets a push to approve or deny; you can't use it until they do. On approval the wallet posts a wake-back to " + card.wake.repo + " PR #" + card.wake.pr + " to resume you — make sure you're watching that PR." };
  }
  return { error: "unknown tool: " + name };
}

async function handleMcp(request, env, principal) {
  let body;
  try { body = await request.json(); } catch { return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
  const messages = Array.isArray(body) ? body : [body];
  const responses = [];
  for (const msg of messages) {
    const isNotification = msg.id === undefined || msg.id === null;
    let res;
    switch (msg.method) {
      case "initialize":
        res = { jsonrpc: "2.0", id: msg.id, result: {
          protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO,
          instructions: "Fort Card wallet — your credentials live here, never in your hands. THE RULE: when you need a credential, your FIRST move is wallet_map. It returns usable_cards (spend now), requestable_secrets (keys the owner has stored but that have no card yet — ask_card for one, the owner approves on their phone), and pending_cards. If what you need is a usable card -> use_card (the real key is injected server-side; you never see it). If it's a requestable secret -> ask_card. If it's in NEITHER, the owner has not stored that key -> tell them exactly which key to add to their wallet; never improvise or hold a raw key. When you ask_card you MUST pass a wake target (repo + pr): on approval the wallet posts a comment to that PR to resume you — if you're an interactive session with no PR, open one first as your listening post and watch it. You can never issue, approve, or recharge a card yourself — that is always the owner's tap.",
        } };
        break;
      case "ping": res = { jsonrpc: "2.0", id: msg.id, result: {} }; break;
      case "tools/list": res = { jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } }; break;
      case "tools/call": {
        const { name, arguments: args } = msg.params || {};
        const out = await callTool(name, args || {}, env, principal);
        res = { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] } };
        break;
      }
      default: res = { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found: " + msg.method } };
    }
    if (!isNotification) responses.push(res);
  }
  if (responses.length === 0) return new Response(null, { status: 202 });
  return Response.json(Array.isArray(body) ? responses : responses[0], { headers: { "Mcp-Session-Id": principal.space } });
}
