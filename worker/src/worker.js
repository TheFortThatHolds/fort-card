// Fort Card — a self-hostable credential card-network for the agent era.
//
// Issue API credentials like CREDIT CARDS, not keys: scoped, capped, freezable pointers at
// secrets that live encrypted in your vault. When a card is "charged," the real key is
// injected server-side and the upstream response is returned — the caller NEVER sees the
// key. Steal a card → it's locked to one host, capped, and freezable. Steal a key → game over.
//
// MULTI-TENANT. Every record is walled behind a SPACE prefix, so one deployment can host many
// tenants — each sealed in its own space with its own secrets, cards, statement, AND its own
// data key. Today the space is resolved from the owner/agent token (a single space,
// `FORT_SPACE`, default "owner"); OAuth sign-in (GitHub / Google) maps each verified identity
// to its own space, so strangers self-onboard and never see across. Self-host stays single-
// tenant for free — you just never add a second space.
//
// HUMAN-IN-THE-LOOP. A per-card limit means nothing if the holder can mint a fresh card or
// refill its own allowance — so ISSUING and RE-AUTHORIZING (unfreezing) a card are OWNER acts.
// This worker tells human from agent by WHICH TOKEN is presented:
//   • FORT_KEY        the owner. Issues ACTIVE cards, approves/unfreezes, stores secrets, rotates.
//   • FORT_AGENT_KEY  (optional) an agent. May request/use/freeze/revoke — but a card it
//                     issues is PENDING (inert) until the owner approves it in the wallet.
// If FORT_AGENT_KEY is unset, only the owner token works and every issue is active (the old
// single-token behaviour, unchanged).
//
// Every act writes a line to the STATEMENT — an append-only events ledger (GET /events). The
// ledger never contains a key or a secret value; it's the audit trail, not the vault.
//
// One file, no dependencies, runs on Cloudflare Workers. Fork it, read it, run your own.
//
// HTTP API (all routes require  Authorization: Bearer <FORT_KEY | FORT_AGENT_KEY>):
//   POST   /secrets            {name, value}                       store a secret (owner only)
//   POST   /rotate                                                 rotate the vault key (owner only)
//   POST   /cards              {name, secret, allowed_hosts, ...}  issue (owner) / request (agent)
//   GET    /cards                                                  list cards (never the key)
//   GET    /events             ?limit=N                            the statement (audit ledger)
//   GET    /events/export                                          download the FULL ledger (file)
//   POST   /cards/:id/use      {url, method?, headers?, body?}     charge: authorize + settle
//   POST   /cards/:id/freeze   {frozen}                            freeze (any) / unfreeze (owner)
//   DELETE /cards/:id                                              revoke
//
// Bindings (see wrangler.toml):
//   KV namespace `VAULT`
//   secret `FORT_KEY`        owner bearer token you choose
//   secret `FORT_AGENT_KEY`  (optional) agent bearer token — its issues land pending
//   secret `MASTER_KEY`      base64 of 32 random bytes:  openssl rand -base64 32
//   var    `FORT_SPACE`      (optional) the space for the owner/agent token (default "owner")
//   var    `NOTIFY_WEBHOOK`  (optional) URL that gets a JSON POST when an agent requests a card
//                            (best-effort; the hosted Core fans this out to email + web-push)
//   secret `STRIPE_KEY`     (optional) turns on SUBSCRIPTIONS. The operator's Stripe key as a Worker
//                            secret — billing reads it directly to open Checkout sessions and confirm
//                            subscriptions (no webhook, no dashboard button, no key in the repo, never
//                            in a tenant vault). `STRIPE_PRICE_ID` (var) reuses an existing price
//                            instead of auto-creating one. Unset = billing off (self-host runs free).
//
// Monetization is binary and AT THE DOOR: when STRIPE_KEY is set, an OAuth tenant must hold an
// active subscription before any wallet USE (store/issue/charge/approve/mint). They can still sign
// in, see their empty space, and subscribe. Self-host (FORT_KEY) and agent tokens are never gated.

import { handleAuth, resolveSession, oauthConfigured, verify, sign, readCookie } from "./auth.js";
import { handlePasskey, requireStepUp } from "./webauthn.js";
import { resolveAgentBearer, mintAgentBearer, listAgents, revokeAgent } from "./agents.js";
import { handleApp } from "./app.js";
import { mintSealTicket } from "./ticket.js";
import { mintClaimCode, verifyAndConsumeClaim } from "./claim.js";
import * as cf from "./cloudflare.js";
import { pushToOwner, addSubscription, removeSubscription, vapidPublicKey, listSubscriptions } from "./push.js";
import { postComment, appConfigured, getInstallationOwner } from "./github-app.js";
import { isSubscribed, createCheckout, confirmCheckout, priceCents, billingSummary, cancelSubscription, resumeSubscription, listBilledSpaces, getBilling, putBilling, clearBillingIndex } from "./stripe.js";
import { sendWelcomeEmail, sendCancelEmail, sendResumeEmail, sendLapseEmail, sendPurgeReminderEmail, emailConfigured } from "./email.js";
import { handleConnect } from "./connect.js";
import { CardState } from "./cardstate.js";
import { OnceGate } from "./oncegate.js";
// Durable Object classes must be exported from the Worker's entry module so the runtime can bind them.
export { CardState, OnceGate };

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json" } });

const HUMAN_REQUIRED =
  "Human-in-the-loop required: issuing or re-authorizing a Fort Card is an owner act. " +
  "Present the owner token (FORT_KEY) to do it — an agent token cannot issue an active " +
  "card, store a secret, refill its own allowance, or rotate the vault. (Agents may use, freeze, revoke.)";

// Every record is namespaced by the tenant's space — the hard isolation boundary. Deny by
// default: no key is ever read or written without a space in front of it.
export const K = (space, ...parts) => space + ":" + parts.join(":");

// ── Card live state lives in the CardState Durable Object (one instance per card) — the strongly-
// consistent home for frozen/revoked/used so a freeze/revoke is instant and a spend can only
// consume. A KV index of card IDs per space lets us enumerate a space's cards for listing; each
// card's authoritative state is always read fresh from its DO. ──
function cardDO(env, space, id) {
  return env.CARD_STATE.get(env.CARD_STATE.idFromName(space + ":" + id));
}
export async function cardOp(env, space, id, op, payload) {
  const r = await cardDO(env, space, id).fetch("https://do/" + op, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload || {}),
  });
  return r.json();
}
const cardIdxPrefix = (space) => K(space, "cardidx", "");
export async function registerCard(env, space, id) { await env.VAULT.put(cardIdxPrefix(space) + id, "1"); }
export async function unregisterCard(env, space, id) { await env.VAULT.delete(cardIdxPrefix(space) + id); }
// One-time, idempotent migration: import legacy KV card records (K(space,"card",id), the pre-DO
// home) into each card's Durable Object + the id index, so existing cards survive the cutover.
// Marked done with a per-space flag so it runs at most once. Old KV records are left in place (inert).
export async function migrateSpaceCards(env, space) {
  if (await env.VAULT.get(K(space, "cardidx_migrated"))) return;
  let cursor;
  const prefix = K(space, "card", "");
  do {
    const page = await env.VAULT.list({ prefix, cursor });
    for (const k of page.keys) {
      const raw = await env.VAULT.get(k.name);
      if (!raw) continue;
      let c; try { c = JSON.parse(raw); } catch { continue; }
      const id = k.name.slice(prefix.length);
      await cardOp(env, space, id, "init", { card: c });
      await registerCard(env, space, id);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  await env.VAULT.put(K(space, "cardidx_migrated"), new Date().toISOString());
}

// Every live card record in a space (authoritative state from each DO; stale index entries skipped).
export async function listCardStates(env, space) {
  await migrateSpaceCards(env, space);
  const out = [];
  let cursor;
  const prefix = cardIdxPrefix(space);
  do {
    const page = await env.VAULT.list({ prefix, cursor });
    for (const k of page.keys) {
      const c = await cardOp(env, space, k.name.slice(prefix.length), "status");
      if (c) out.push(c);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// ── envelope encryption: MASTER_KEY is the KEK (the sovereign root — never rotated in-app);
// under it, each SPACE has its own rotatable DATA key (DEK) in KV, wrapped by the KEK. A tenant
// can mint a fresh DEK and re-seal their secrets (POST /rotate, owner only) without touching
// any other space — the KEK never changes, so a rotation can NEVER lock anyone out, and a
// leaked agent token can never re-key. A secret sealed before the space's first rotation carries
// no keyRef and still opens under the KEK. ──
async function kek(env) {
  return crypto.subtle.importKey("raw", b64d(env.MASTER_KEY), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
const dekCache = new Map(); // keyed by space:ref; rotation mints a new ref, so never stale
async function importRaw(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function loadDEK(env, space, ref) {
  const cacheKey = space + ":" + ref;
  if (dekCache.has(cacheKey)) return dekCache.get(cacheKey);
  const raw = await env.VAULT.get(K(space, "dek", ref));
  if (!raw) throw new Error("vault data key '" + ref + "' missing");
  const w = JSON.parse(raw);
  const dekRaw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(w.iv) }, await kek(env), b64d(w.ct));
  const key = await importRaw(new Uint8Array(dekRaw));
  dekCache.set(cacheKey, key);
  return key;
}
// key to SEAL new writes in a space with: that space's active DEK once rotated, else the KEK
// (pre-rotation = original behaviour). key to OPEN a secret: its keyRef's DEK, else the KEK.
async function writeKey(env, space) {
  const ref = await env.VAULT.get(K(space, "dek", "active"));
  return ref ? { key: await loadDEK(env, space, ref), ref } : { key: await kek(env), ref: null };
}
async function readKey(env, space, keyRef) {
  return keyRef ? loadDEK(env, space, keyRef) : kek(env);
}
async function sealWith(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { iv: b64e(iv.buffer), ct: b64e(ct) };
}
async function encrypt(env, space, plaintext) {
  const { key, ref } = await writeKey(env, space);
  const s = await sealWith(key, plaintext);
  if (ref) s.keyRef = ref;
  return s;
}
async function decrypt(env, space, s) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(s.iv) }, await readKey(env, space, s.keyRef), b64d(s.ct));
  return dec.decode(pt);
}
// Mint a fresh DEK for ONE space, wrap it under the KEK, make it active, and re-seal that
// space's secrets to it. Other spaces and the KEK are untouched. Owner-gated by the route.
async function rotateDataKey(env, space) {
  const rawDek = crypto.getRandomValues(new Uint8Array(32));
  const ref = "dek_" + crypto.randomUUID().slice(0, 8);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await kek(env), rawDek);
  await env.VAULT.put(K(space, "dek", ref), JSON.stringify({ ref, iv: b64e(iv.buffer), ct: b64e(wrapped), created: new Date().toISOString() }));
  const newKey = await importRaw(rawDek);
  dekCache.set(space + ":" + ref, newKey);
  await env.VAULT.put(K(space, "dek", "active"), ref); // active before re-seal, so concurrent writes land here too
  let rotated = 0;
  let cursor;
  const prefix = K(space, "secret", "");
  do {
    const page = await env.VAULT.list({ prefix, cursor });
    for (const k of page.keys) {
      const raw = await env.VAULT.get(k.name);
      if (!raw) continue;
      const plain = await decrypt(env, space, JSON.parse(raw)); // opens under its OLD keyRef / the KEK
      const sealed = await sealWith(newKey, plain);
      sealed.keyRef = ref;
      await env.VAULT.put(k.name, JSON.stringify(sealed));
      rotated++;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return { ref, rotated };
}

// ── the statement: an append-only ledger of every act (never a key, never a secret value) ──
export async function logEvent(env, space, type, data) {
  const ts = new Date().toISOString();
  // ts in the key → KV lists lexicographically, so we read newest-first by reversing.
  await env.VAULT.put(K(space, "event", ts, crypto.randomUUID().slice(0, 8)), JSON.stringify({ ts, type, ...data }));
}

// Wipe an ENTIRE space's KV: every key under the "<space>:" prefix — secrets, the card index, legacy
// card records, bearers, events, billing, passkeys, push subscriptions, DEKs, the lot. The colon
// delimiter makes the prefix exact, so a space named "ab" can never catch "abc:". Paginates past 1000
// keys. NOTE: card LIVE state lives in CardState Durable Objects (outside KV) — eraseSpace() drops
// those first; this only clears KV. Used by on-demand erasure (GDPR Art 17) and the lapse purge.
export async function purgeSpace(env, space) {
  const prefix = space + ":";
  let cursor;
  let deleted = 0;
  do {
    const page = await env.VAULT.list({ prefix, cursor });
    for (const k of page.keys) {
      await env.VAULT.delete(k.name);
      deleted++;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return deleted;
}

// Build the full data export for a space (GDPR Arts 15 & 20): the whole statement, card configs, the
// NAMES of stored secrets (never values — the wallet can't read them), and the billing summary.
// Card state is read from the authoritative source (each card's Durable Object via listCardStates),
// not raw KV — new cards live only in their DO + the id index. Shared by the in-app /export route and
// the signed email download link.
export async function buildExport(env, space) {
  const events = [];
  {
    let cursor;
    const ep = K(space, "event", "");
    do {
      const page = await env.VAULT.list({ prefix: ep, cursor });
      for (const k of page.keys) { const raw = await env.VAULT.get(k.name); if (raw) events.push(JSON.parse(raw)); }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    events.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0)); // newest first
  }
  const cards = (await listCardStates(env, space)).map((c) => ({
    id: c.id, name: c.name, secret: c.secret, allowed_hosts: c.allowed_hosts, limit: c.limit,
    used: c.used, holder: c.holder ?? null, expires_at: c.expires_at ?? null, frozen: !!c.frozen, pending: !!c.pending,
  }));
  const sp = K(space, "secret", "");
  const slist = await env.VAULT.list({ prefix: sp });
  const secret_names = slist.keys.map((k) => k.name.slice(sp.length));
  const billing = await billingSummary(env, space);
  return {
    space,
    generated_at: new Date().toISOString(),
    note: "Your Fort Card data export. Secret VALUES are never included — the wallet cannot read them.",
    billing,
    secret_names,
    cards,
    events,
  };
}

// Erase a space: stop future billing (best-effort — never block erasure on Stripe), drop every card's
// live state from its Durable Object (DO storage lives OUTSIDE the KV prefix, so purgeSpace alone
// would orphan it), wipe every KV key under the prefix, then drop the billing-index entry. Shared by
// the in-app /erase, the signed email delete link, and the 30-day lapse purge. Irreversible.
export async function eraseSpace(env, space, charge) {
  if (charge) { try { await cancelSubscription(env, charge, space); } catch (_) { /* keep going */ } }
  try {
    for (const c of await listCardStates(env, space)) {
      try { await cardOp(env, space, c.id, "revoke"); } catch (_) { /* per-card best-effort */ }
    }
  } catch (_) { /* never block erasure on a DO read */ }
  const deleted = await purgeSpace(env, space);
  try { await clearBillingIndex(env, space); } catch (_) { /* index is best-effort */ }
  return deleted;
}

const escapeHtml = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
// Confirm page reached by the email "Delete my data" link — a GET click here deletes NOTHING; the
// button POSTs back with the same signed token. (Email scanners prefetch links, so the GET is inert.)
const deleteConfirmPage = (tokenQ) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Delete your Fort Card data</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#1a1611;color:#efe7da;max-width:560px;margin:0 auto;padding:48px 22px;line-height:1.55">
<h2 style="margin:0 0 14px">Delete your Fort Card data</h2>
<p style="color:#9a8f7d">This permanently deletes everything in your space — your secrets, cards, agent bearers, and statement. It cannot be undone.</p>
<form method="POST" action="/data/delete?token=${escapeHtml(tokenQ)}">
<button type="submit" style="background:#3a201c;color:#e7857a;border:1px solid #5a3a36;padding:13px 20px;border-radius:10px;font-size:16px;cursor:pointer">Yes, permanently delete everything</button>
</form>
<p style="color:#6b6155;font-size:13px;margin-top:26px">Changed your mind? Just close this page — nothing is deleted unless you tap the button above.</p>
</body></html>`;
const deletedPage = () => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Deleted</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#1a1611;color:#efe7da;max-width:560px;margin:0 auto;padding:48px 22px;line-height:1.55">
<h2 style="margin:0 0 14px">Your data has been deleted</h2>
<p style="color:#9a8f7d">Everything in your Fort Card space has been permanently erased. Thank you for having trusted Fort Card with your keys.</p>
</body></html>`;

// ── THE LAPSE LIFECYCLE (run by the scheduled() cron). For every billed space: if the subscription is
// active, clear any pending-lapse state. If it lapsed, open a 30-day grace window (email the customer a
// re-up + signed download + signed delete link), warn 7 days before the deadline, and finally — only
// when PURGE_ENABLED is set — permanently wipe the space. Ships DORMANT: with PURGE_ENABLED unset the
// sweep does everything EXCEPT the actual delete (it logs purge_due so the operator can watch it run dry).
const GRACE_MS = 30 * 24 * 60 * 60 * 1000;
const REMIND_BEFORE_MS = 7 * 24 * 60 * 60 * 1000;
export async function runLifecycle(env) {
  if (!env.STRIPE_KEY) return { ran: false, reason: "billing off" }; // nothing can lapse
  const charge = stripeCharge(env);
  const origin = env.WALLET_ORIGIN || "";
  const purgeArmed = env.PURGE_ENABLED === "1" || env.PURGE_ENABLED === "true";
  const now = Date.now();
  const spaces = await listBilledSpaces(env);
  let lapsed = 0, reminded = 0, purged = 0, purgeDue = 0, restored = 0;
  for (const space of spaces) {
    try {
      const rec = await getBilling(env, space);
      if (!rec) { await clearBillingIndex(env, space); continue; } // stale index entry
      const active = await isSubscribed(env, charge, space); // refreshes rec.status from Stripe
      if (active) {
        if (rec.lapsed_at || rec.purge_at) { // re-upped inside the grace window — stand down
          delete rec.lapsed_at; delete rec.purge_at; delete rec.lapse_reminded;
          rec.updated = now; await putBilling(env, space, rec);
          await logEvent(env, space, "billing.resumed_from_lapse", {});
          restored++;
        }
        continue;
      }
      // ── lapsed ──
      const mkLink = async (action) => origin + "/data/" + (action === "export" ? "download" : "delete") +
        "?token=" + (await sign(env, { kind: "datalink", action, space, exp: (rec.purge_at || now + GRACE_MS) }));
      if (!rec.lapsed_at) {
        rec.lapsed_at = now; rec.purge_at = now + GRACE_MS; rec.updated = now;
        await putBilling(env, space, rec);
        await logEvent(env, space, "billing.lapsed", { purge_at: rec.purge_at });
        if (emailConfigured(env) && rec.email) {
          const mail = await sendLapseEmail(env, { to: rec.email, space, origin, downloadUrl: await mkLink("export"), deleteUrl: await mkLink("erase"), purge_at: rec.purge_at });
          await logEvent(env, space, "billing.lapse_email", mail);
        }
        lapsed++;
        continue;
      }
      if (!rec.lapse_reminded && now >= rec.purge_at - REMIND_BEFORE_MS && now < rec.purge_at) {
        rec.lapse_reminded = true; rec.updated = now; await putBilling(env, space, rec);
        if (emailConfigured(env) && rec.email) {
          const mail = await sendPurgeReminderEmail(env, { to: rec.email, space, origin, downloadUrl: await mkLink("export"), deleteUrl: await mkLink("erase"), purge_at: rec.purge_at });
          await logEvent(env, space, "billing.purge_reminder_email", mail);
        }
        reminded++;
      }
      if (now >= rec.purge_at) {
        if (purgeArmed) {
          await eraseSpace(env, space, charge);
          // The space is gone; leave a tombstone OUTSIDE its prefix for audit (not customer data).
          await env.VAULT.put("_tombstone:" + space, JSON.stringify({ purged_at: now, reason: "lapse_grace_expired" }), { expirationTtl: 400 * 24 * 60 * 60 });
          purged++;
        } else {
          await logEvent(env, space, "billing.purge_due", { since: rec.purge_at, note: "PURGE_ENABLED not set — dry run, nothing deleted" });
          purgeDue++;
        }
      }
    } catch (e) {
      // one space failing must never abort the whole sweep
      try { await logEvent(env, space, "billing.lifecycle_error", { error: (e && e.message) || "unknown" }); } catch (_) {}
    }
  }
  return { ran: true, spaces: spaces.length, lapsed, reminded, purged, purgeDue, restored, purgeArmed };
}

// ── THE LOCKBOX: sealing, opening, injecting, and fetching all happen in the customer's OWN
// lockbox worker, on the customer's OWN Cloudflare. THIS worker (the control plane) holds only
// ciphertext and never touches MASTER_KEY — it relays sealed material to the customer's lockbox,
// which opens it on the customer's infra. See the lockbox worker (last-mile/). ──
// Per-space lockbox: each customer points the control plane at THEIR OWN lockbox worker (on their
// Cloudflare). We store only the URL + the relay token needed to reach it — never a customer's API
// key. A global LAST_MILE_URL/KEY remains only as a single-deployment fallback.
export async function lastMileConfig(env, space) {
  if (space) {
    const raw = await env.VAULT.get(K(space, "lastmile", "config"));
    if (raw) { try { const c = JSON.parse(raw); if (c && c.url && c.key) return c; } catch {} }
  }
  if (env.LAST_MILE_URL && env.LAST_MILE_KEY) return { url: env.LAST_MILE_URL, key: env.LAST_MILE_KEY };
  return null;
}
export async function splitMode(env, space) {
  return !!(await lastMileConfig(env, space));
}
async function callLastMile(env, space, path, payload) {
  const cfg = await lastMileConfig(env, space);
  if (!cfg) throw new Error("no lockbox configured for this space");
  const resp = await fetch(cfg.url.replace(/\/+$/, "") + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + cfg.key },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error("lockbox " + path + " failed: " + resp.status);
  return resp.json();
}
// the space's active KEK-wrapped DEK ({iv, ct}) to hand the lockbox worker, or null pre-rotation.
async function activeWrappedDEK(env, space) {
  const ref = await env.VAULT.get(K(space, "dek", "active"));
  if (!ref) return null;
  const raw = await env.VAULT.get(K(space, "dek", ref));
  return raw ? JSON.parse(raw) : null;
}
// the KEK-wrapped DEK for a secret's specific keyRef (what opens THAT secret), or null.
async function wrappedDEKFor(env, space, keyRef) {
  if (!keyRef) return null;
  const raw = await env.VAULT.get(K(space, "dek", keyRef));
  return raw ? JSON.parse(raw) : null;
}

// best-effort owner notification when an agent requests a card; never blocks issuance.
// Two channels: a Web Push to the owner's installed wallet (so it buzzes), and the optional
// NOTIFY_WEBHOOK relay. Both are wrapped so a failure never blocks the request landing.
export async function notifyCardRequest(env, space, card) {
  const limit = card.limit != null ? String(card.limit) : "unlimited";
  await pushToOwner(env, space, {
    title: "Fort Card approval needed",
    body: `${card.name} → ${card.allowed_hosts.join(", ")} (limit ${limit}). Tap to approve.`,
    url: "/app",
  });
  if (!env.NOTIFY_WEBHOOK) return;
  try {
    await fetch(env.NOTIFY_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "fort-card.request",
        text: `Fort Card approval needed: ${card.name} → ${card.allowed_hosts.join(", ")} (limit ${limit})`,
        card: { id: card.id, name: card.name, secret: card.secret, allowed_hosts: card.allowed_hosts, limit: card.limit },
      }),
    });
  } catch {
    /* never block card creation on a notification */
  }
}

// ── the WAKE-BACK (DESIGN §8): when the owner approves a pending card, post a comment to the
// REQUESTER's own repo/PR — never the public fort-card repo — so the agent's subscribed session
// wakes and resumes immediately. The write permission comes from the ONE Fort Wallet GitHub App
// being INSTALLED on that repo by its owner (an install token, scoped to consented repos) — no
// operator PAT, no per-customer app. App unset / not installed there = the push already notified
// the human; no auto-wake. Best-effort; the approval itself never blocks on it. ──
async function wakeRequester(env, space, card) {
  const w = card.wake;
  if (!w || !w.repo || !w.pr) return;
  if (!appConfigured(env)) {
    await logEvent(env, space, "card.wake_skip", { id: card.id, reason: "GitHub App not configured (GH_APP_ID/GH_APP_PRIVATE_KEY)" });
    return;
  }
  try {
    const ok = await postComment(env, w.repo, w.pr, `✅ **Fort Card approved** — \`${card.name}\` (card \`${card.id}\`) is now active. Resume.`);
    await logEvent(env, space, ok ? "card.wake" : "card.wake_skip", { id: card.id, repo: w.repo, pr: w.pr, reason: ok ? undefined : "app not installed on that repo" });
  } catch (e) {
    await logEvent(env, space, "card.wake_skip", { id: card.id, repo: w.repo, reason: (e && e.message) || "wake failed" });
  }
}

// ── SSRF guard: refuse private / loopback / link-local / cloud-metadata targets. The card's
// allowed_hosts is the merchant allowlist; this is the second, network-layer fence, enforced at
// the control plane BEFORE a charge so a misconfigured card can never point the key at an internal
// address. (The lockbox worker re-checks this too — belt and suspenders.) ──
export function ssrfBlocked(host) {
  let h = host.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  const mapped = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/); // IPv4-mapped IPv6 → test the embedded v4
  if (mapped) h = mapped[1];
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "::1" || h === "::" || h === "0.0.0.0" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  if (/^\d+$/.test(h)) return true; // integer-encoded IP (2130706433 = 127.0.0.1)
  if (/^0x[0-9a-f]+$/.test(h)) return true; // hex-encoded IP (0x7f000001)
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true; // malformed octet → refuse rather than guess
    const [a, b] = o;
    if (a === 127 || a === 10 || a === 0) return true; // loopback / private / this-host
    if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
    if (a === 192 && b === 168) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  }
  if (/^[0-9.]+$/.test(h) && /(^|\.)0\d/.test(h)) return true; // octal-smuggled octet (0177.0.0.1)
  return false;
}

// ── BILLING runs on the operator's Stripe key — a Cloudflare WORKER SECRET (STRIPE_KEY): operator
// infrastructure, encrypted at rest by the platform, never in a tenant vault, never agent-reachable,
// never in the repo. We hand stripe.js a `charge(req)→{status,body}` that calls Stripe directly with
// that key. Billing is OFF (everyone passes) until STRIPE_KEY is set — so self-host stays free. ──
function stripeCharge(env) {
  return async (req) => {
    const r = await fetch(req.url, {
      method: req.method || "GET",
      headers: { Authorization: "Bearer " + env.STRIPE_KEY, ...(req.headers || {}) },
      body: req.body,
    });
    const text = await r.text();
    let body; try { body = JSON.parse(text); } catch { body = text; }
    return { status: r.status, body };
  };
}

// Hosted-billing gate, shared by the REST agent door and the MCP connect door: on a managed
// instance (STRIPE_KEY set) only a SUBSCRIBED space may connect or use. Self-host (no STRIPE_KEY)
// returns true — they run their own infra; nothing to pay the operator.
export async function spaceSubscribed(env, space) {
  if (!env.STRIPE_KEY) return true;
  return await isSubscribed(env, stripeCharge(env), space);
}

// ── spend a card in a space (the settle path, shared by /cards/:id/use and the agent path): the
// CardState DO atomically fences (revoked/frozen/pending/expired/cap/host) AND counts the spend in
// one serialized step, then we inject the key server-side and return only the response. The spend
// NEVER writes card state itself — so it can never resurrect a revoked card or clobber a freeze. ──
export async function chargeCard(env, space, id, req) {
  const decline = async (reason) => { await logEvent(env, space, "card.decline", { id, reason }); return { authorized: false, decline_reason: reason }; };
  if (!req || !req.url) return decline("request url required");
  let host;
  try { host = new URL(req.url).host; } catch { return decline("bad url"); }
  if (ssrfBlocked(host)) return decline(`host ${host} blocked (SSRF)`);

  await migrateSpaceCards(env, space); // import any legacy KV card into its DO before first spend
  // Atomic reserve: fence + increment happen together inside the card's Durable Object. If it
  // declines (frozen/revoked/expired/over-cap/off-host) nothing is consumed and we never touch state.
  const res = await cardOp(env, space, id, "reserve", { host });
  if (!res.authorized) return decline(res.decline_reason || "declined");
  const card = res.card; // the live record the DO just reserved against (has secret name + header)

  const secRaw = await env.VAULT.get(K(space, "secret", card.secret));
  if (!secRaw) return decline("secret missing from vault");
  const sealed = JSON.parse(secRaw);
  let resp, out;
  if (await splitMode(env, space)) {
    const r = await callLastMile(env, space, "/charge", { secret: sealed, dek: await wrappedDEKFor(env, space, sealed.keyRef), header: card.header, header_prefix: card.header_prefix, request: { url: req.url, method: req.method || "GET", headers: req.headers || {}, body: req.body } });
    resp = { status: r.status }; out = r.body;
  } else {
    const key = await decrypt(env, space, sealed);
    const httpResp = await fetch(req.url, { method: req.method || "GET", headers: { ...(req.headers || {}), [card.header]: card.header_prefix + key }, body: req.body == null ? undefined : typeof req.body === "string" ? req.body : JSON.stringify(req.body) });
    const text = await httpResp.text();
    try { out = JSON.parse(text); } catch { out = text; }
    resp = { status: httpResp.status };
  }
  await logEvent(env, space, "card.charge", { id, holder: card.holder || null, host, method: req.method || "GET", status: resp.status, used: card.used, limit: card.limit ?? null });
  return { authorized: true, status: resp.status, body: out, card: { id, used: card.used, remaining: card.limit != null ? Math.max(0, card.limit - card.used) : null } };
}

export default {
  async fetch(request, env) {
    // Crypto must be reachable (a connected lockbox, or a MASTER_KEY on this worker), and at least
    // one way to authenticate: the self-host owner token (FORT_KEY) and/or GitHub-App OAuth login
    // (the SaaS path). A pure self-host sets FORT_KEY; a managed instance configures OAuth.
    const cryptoReady = env.MASTER_KEY || (env.LAST_MILE_URL && env.LAST_MILE_KEY) || oauthConfigured(env);
    const authReady = env.FORT_KEY || oauthConfigured(env);
    if (!cryptoReady || !authReady) {
      return json({ error: "server not configured — need MASTER_KEY (or LAST_MILE_URL + LAST_MILE_KEY), and FORT_KEY or the GitHub-App OAuth vars (GH_CLIENT_ID/SECRET/CALLBACK_URL)" }, 500);
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/") return json({ name: "fort-card", ok: true, docs: "https://github.com/TheFortThatHolds/fort-card" });

    // ── DATA RIGHTS via a SIGNED LINK (works while LOCKED OUT — e.g. after a lapse, from the email).
    // The signed token IS the auth (one-way {kind:"datalink", action, space, exp}); no session needed.
    // Download is read-only (GET). Delete is two-step even from email: GET returns an inert confirm
    // page, the POST actually erases. These sit before the auth gate ON PURPOSE. ──
    if (path === "/data/download" && request.method === "GET") {
      const claim = await verify(env, url.searchParams.get("token") || "");
      if (!claim || claim.kind !== "datalink" || claim.action !== "export" || !claim.space) return json({ error: "invalid or expired link" }, 401);
      const data = await buildExport(env, claim.space);
      return new Response(JSON.stringify(data, null, 2), { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="fort-card-export-${(data.generated_at || "").slice(0, 10)}.json"` } });
    }
    if (path === "/data/delete" && (request.method === "GET" || request.method === "POST")) {
      const claim = await verify(env, url.searchParams.get("token") || "");
      if (!claim || claim.kind !== "datalink" || claim.action !== "erase" || !claim.space) return json({ error: "invalid or expired link" }, 401);
      if (request.method === "GET") {
        return new Response(deleteConfirmPage(url.searchParams.get("token") || ""), { headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
      await eraseSpace(env, claim.space, env.STRIPE_KEY ? stripeCharge(env) : null);
      return new Response(deletedPage(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // The wallet PWA (and its manifest / service worker). Public HTML — the page itself drives
    // auth via /whoami. This same page is what Fort Core embeds as the plugin (?embed=1).
    const appResp = handleApp(env, request, url, path);
    if (appResp) return appResp;

    // Identity routes (login / callback / logout / whoami). When OAuth is unconfigured these
    // don't exist and handleAuth returns null — the self-host bearer path below is unchanged.
    const authResp = await handleAuth(request, env, url, path);
    if (authResp) return authResp;

    // ── AGENT CONNECT DOOR: OAuth sign-in + the MCP endpoint an agent connects through. Returns a
    // Response if it handled the path, else null (same shape as handleAuth). This is the customer-
    // facing door — the owner uses it too, as customer #1; there is no separate operator path. ──
    const connectResp = await handleConnect(request, env, url, path);
    if (connectResp) return connectResp;

    // ── AGENT-FACING discovery + request. No wallet credential: the agent names the repo it's
    // working in, and the Fort Wallet GitHub App being INSTALLED there resolves the owner's space.
    // Returns NAMES + hosts only, never key values. /request lands a PENDING card for the owner to
    // approve (push + wake-back). v1 gate = app-installed-on-repo; hardening (require repo-write
    // proof so randoms can't spam the queue) is the next layer. ──
    if ((path === "/agent/discover" || path === "/agent/request" || path === "/agent/use") && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!b.repo) return json({ error: "repo required (owner/name) — the repo you're working in" }, 400);
      if (!appConfigured(env)) return json({ error: "wallet not set up for app-based requests" }, 503);
      let aspace;
      try {
        const o = await getInstallationOwner(env, b.repo);
        aspace = "github:" + o.id;
      } catch (e) {
        return json({ error: (e && e.message) || ("Fort Wallet not installed on " + b.repo) }, 403);
      }
      // Billing is at the door for agents too: an agent may only touch a space whose owner is
      // subscribed. Billing off (no Stripe card issued) passes straight through.
      if (env.STRIPE_KEY && !(await isSubscribed(env, stripeCharge(env), aspace))) {
        return json({ error: "this space's Fort Card subscription is inactive — the owner must subscribe in the wallet", code: "subscribe_required" }, 402);
      }
      if (path === "/agent/discover") {
        const usable = (await listCardStates(env, aspace))
          .filter((c) => !c.pending && !c.frozen)
          .map((c) => ({ id: c.id, name: c.name, allowed_hosts: c.allowed_hosts, remaining: c.limit != null ? Math.max(0, c.limit - c.used) : null }));
        const secPrefix = K(aspace, "secret", "");
        const secList = await env.VAULT.list({ prefix: secPrefix });
        const requestable = secList.keys.map((k) => k.name.slice(secPrefix.length));
        return json({
          usable_cards: usable,
          requestable_secrets: requestable,
          push_subscriptions: (await listSubscriptions(env, aspace)).length,
          note: "Charge a usable card with /cards/:id/use. To get a new one: POST /agent/request {repo, pr, secret, allowed_hosts} — it lands pending for the owner to approve, then the wake-back posts to your PR.",
        });
      }
      if (path === "/agent/use") {
        // Spend a card the owner already approved in this space. An approved card is a BEARER: any
        // agent in this space may charge it — there is no requester-lock on spend. The real controls
        // live in the card's DO and travel WITH the card: it must be approved (not pending), not
        // frozen, not expired, under its cap, and the target host must be on its allowed_hosts.
        // Approval + the owner's wake-back gate getting a NEW card or a recharge — never a spend.
        return json(await chargeCard(env, aspace, String(b.card), b.request));
      }
      // /agent/request
      if (!b.secret || !Array.isArray(b.allowed_hosts) || !b.allowed_hosts.length) {
        return json({ error: "secret and a non-empty allowed_hosts array are required" }, 400);
      }
      // A request declares its cap, OR asks for unlimited (e.g. an email sender scoped to one host).
      // Either way it lands PENDING and inert until the owner approves it — the human sees the cap (or
      // "unlimited") and the single allowed host on approval, and the host scope is the real control.
      let limit;
      if (b.unlimited === true || b.charges === "unlimited" || b.limit === null) {
        limit = null; // open-ended — the owner approves this knowingly; the allowed_hosts scope bounds it
      } else {
        const charges = Number(b.charges != null ? b.charges : b.limit);
        if (!Number.isInteger(charges) || charges < 1) {
          return json({ error: "charges required: a positive integer, OR pass unlimited:true for an open-ended card (e.g. an email sender). Either way it lands pending for the owner to approve." }, 400);
        }
        limit = charges;
      }
      const rid = "card_" + crypto.randomUUID().slice(0, 8);
      const reqCard = {
        id: rid,
        name: b.label || "request from " + b.repo,
        secret: String(b.secret),
        holder: String(b.repo),
        allowed_hosts: b.allowed_hosts.map(String),
        header: "Authorization",
        header_prefix: "Bearer ",
        limit,
        used: 0,
        expires_at: null,
        frozen: true,
        pending: true,
        wake: b.pr ? { repo: String(b.repo), pr: Number(b.pr) } : null,
        created: new Date().toISOString(),
      };
      await cardOp(env, aspace, rid, "init", { card: reqCard });
      await registerCard(env, aspace, rid);
      await logEvent(env, aspace, "card.request", { id: rid, name: reqCard.name, secret: reqCard.secret, allowed_hosts: reqCard.allowed_hosts, limit, repo: b.repo });
      await notifyCardRequest(env, aspace, reqCard);
      const cap = limit == null ? "unlimited charges" : "capped at " + limit + " charge" + (limit > 1 ? "s" : "");
      return json({ ok: true, pending: true, card: rid, note: "Pending the owner's approval (" + cap + ", scoped to " + reqCard.allowed_hosts.join(", ") + "). Once approved it's a bearer card — charge it via /agent/use {repo, card, request}; the owner's approval (and any recharge) is the only gated step." });
    }

    // ── lockbox PHONE-HOME — a freshly-deployed lockbox self-reports its URL, gated only by a
    // one-time claim code the owner minted in the wallet. NO bearer: the claim code resolves the
    // space, and the result lands PENDING (the owner's approve tap is still the gate). This is the
    // friction-killer — the customer types a short code on the deploy screen instead of copying the
    // worker URL back. Lives in the public block, before the auth wall, because the lockbox has no
    // wallet credentials. Keep /lastmile/connect (paste-URL) as the additive fallback. ──
    if (path === "/lockbox/phone-home" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const claim = await verifyAndConsumeClaim(env, String(b.claim_code || ""));
      if (!claim) return json({ error: "invalid or expired claim code" }, 403);
      const ps = claim.space;
      if (!b.relay_token) return json({ error: "relay_token required" }, 400);
      let h;
      try { h = new URL(String(b.url || "")); } catch { return json({ error: "a valid https url is required" }, 400); }
      if (h.protocol !== "https:") return json({ error: "url must be https" }, 400);
      if (ssrfBlocked(h.host)) return json({ error: "url host not allowed" }, 400);
      const lurl = h.origin + h.pathname.replace(/\/+$/, "");
      await env.VAULT.put(K(ps, "lastmile", "pending"), JSON.stringify({ url: lurl, key: String(b.relay_token), requested: new Date().toISOString() }));
      await logEvent(env, ps, "lastmile.phone_home", { url: lurl }); // url only — never the relay token
      await pushToOwner(env, ps, { title: "Lockbox waiting to connect", body: lurl + " phoned home. Tap to approve.", url: "/app" });
      return json({ ok: true, pending: true });
    }

    // WHO is calling, and WHICH space do they operate in?
    //   • OAuth session   → a verified SaaS tenant, operating in their OWN identity-born space.
    //   • FORT_KEY        → the self-host owner (single-tenant, `FORT_SPACE`).
    //   • minted bearer   → an agent the owner provisioned (resolves to its own space).
    //   • FORT_AGENT_KEY  → the self-host single agent (legacy/self-host space).
    const session = await resolveSession(request, env);
    const auth = request.headers.get("Authorization") || "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const ownerToken = !!env.FORT_KEY && bearer === env.FORT_KEY;
    const legacyAgent = !!env.FORT_AGENT_KEY && bearer === env.FORT_AGENT_KEY;
    // A minted bearer carries its own space; only resolve it when it isn't an owner/legacy token.
    const mintedAgent = !session && !ownerToken && !legacyAgent ? await resolveAgentBearer(env, bearer) : null;
    const agent = legacyAgent || !!mintedAgent;
    const human = !!session || ownerToken;
    if (!session && !ownerToken && !agent) return json({ error: "unauthorized" }, 401);
    const space = session ? session.space : mintedAgent ? mintedAgent.space : env.FORT_SPACE || "owner";

    // Passkey enroll + per-action step-up — the banking-app gate. Only an authenticated human in a
    // space reaches these; OAuth-unconfigured self-host never hits them (no session, owner uses a token).
    const pkResp = await handlePasskey(env, request, url, path, human ? { space, human, login: session ? session.login : "owner" } : null);
    if (pkResp) return pkResp;

    // The auth model: GitHub OAuth is the FLOOR — it signs you in, recovers you on any device, and
    // lets you enroll a passkey. A fingerprint tap then UNLOCKS the wallet for a short window
    // (fc_unlock cookie, set on enroll or unlock). Acting requires that unlock — so a browser
    // session alone can view + enroll, but must tap a fingerprint to act. The passkey is never a
    // standalone key: it's re-enrollable via OAuth, so losing a device can never lock you out.
    // (A self-host FORT_KEY caller is an API token, not a browser human — not unlock-gated.)
    const requireUnlock = async () => {
      if (!session) return null;
      const u = await verify(env, readCookie(request, "fc_unlock"));
      if (u && u.kind === "unlock" && u.space === space) return null;
      return json({ error: "locked — unlock with your passkey", code: "unlock_required" }, 401);
    };
    const stepIfSession = async () => requireUnlock();

    // ── BILLING GATE (DESIGN: monetization). At the door, after sign-in, before ANY wallet access.
    // Only applies to managed (OAuth-session) tenants when billing is configured — a self-host
    // FORT_KEY/agent caller is never gated (they don't pay the SaaS operator), which is why
    // `subscribed` is only ever false for a browser session. Enforced SERVER-SIDE below: an
    // unsubscribed session gets nothing but /whoami (handled earlier), the /billing/* routes, and
    // logout — no reads, no writes. The client's Subscribe wall is just the friendly face of this;
    // the server no longer trusts the JS to hold the line.
    const charge = env.STRIPE_KEY ? stripeCharge(env) : null;
    const billingOn = !!env.STRIPE_KEY && !!session;
    const subscribed = billingOn ? await isSubscribed(env, charge, space) : true;
    const requireSub = () =>
      subscribed ? null : json({ error: "subscription required — subscribe in the wallet to use it", code: "subscribe_required" }, 402);

    const body = request.method === "GET" ? {} : await request.json().catch(() => ({}));

    // ── billing routes (session tenants). status is always safe to read; subscribe needs the
    // customer to accept the terms; confirm verifies the Checkout return by querying Stripe. ──
    if (path === "/billing/status" && request.method === "GET") {
      // Surface cancel_at_period_end + current_period_end so the wallet can show "renews <date>" vs.
      // "ends <date>" and the right button. Self-host (billing off) returns the inert defaults.
      const summary = billingOn ? await billingSummary(env, space) : { cancel_at_period_end: false, current_period_end: null };
      return json({ enabled: !!env.STRIPE_KEY, subscribed, price_cents: priceCents(env), ...summary });
    }
    if (path === "/billing/subscribe" && request.method === "POST") {
      if (!session) return json({ error: "sign in to subscribe" }, 401);
      if (!env.STRIPE_KEY) return json({ error: "billing is not enabled on this instance" }, 400);
      if (subscribed) return json({ ok: true, already_subscribed: true });
      // The terms agreement is collected on Stripe's Checkout page (native ToS consent) — no app-side
      // checkbox. Subscribe just opens Checkout, where Stripe shows the agreement before payment.
      try {
        const { url: checkoutUrl, id } = await createCheckout(env, charge, space, url.origin);
        await logEvent(env, space, "billing.checkout", { session: id });
        return json({ url: checkoutUrl });
      } catch (e) {
        return json({ error: (e && e.message) || "could not start checkout" }, 502);
      }
    }
    if (path === "/billing/confirm" && request.method === "POST") {
      if (!session) return json({ error: "sign in first" }, 401);
      if (!env.STRIPE_KEY) return json({ subscribed: true });
      if (!body.session_id) return json({ error: "session_id required" }, 400);
      try {
        const r = await confirmCheckout(env, charge, space, body.session_id);
        if (r.subscribed) await logEvent(env, space, "billing.active", { subscription: r.subscription });
        // Welcome/thank-you email on the FIRST activation only (firstActivation guards re-sends on a
        // duplicate confirm). Best-effort: a Resend hiccup must never fail the subscription confirm.
        if (r.subscribed && r.firstActivation && emailConfigured(env)) {
          const mail = await sendWelcomeEmail(env, { to: r.email, space, origin: url.origin });
          await logEvent(env, space, "billing.welcome_email", mail);
        }
        return json(r);
      } catch (e) {
        return json({ error: (e && e.message) || "could not confirm checkout" }, 502);
      }
    }
    // Cancel — one tap, no maze. DECISION: at period end (keep what you paid for, then lapse).
    // Reversible via /billing/resume until the period actually ends. Sits with the other /billing/*
    // routes ABOVE the door so it's always reachable by a signed-in tenant.
    if (path === "/billing/cancel" && request.method === "POST") {
      if (!session) return json({ error: "sign in first" }, 401);
      if (!env.STRIPE_KEY) return json({ error: "billing is not enabled on this instance" }, 400);
      try {
        const r = await cancelSubscription(env, charge, space);
        if (r.ok) {
          await logEvent(env, space, "billing.cancel_scheduled", { current_period_end: r.current_period_end });
          if (emailConfigured(env)) {
            const mail = await sendCancelEmail(env, { to: r.email, space, origin: url.origin, current_period_end: r.current_period_end });
            await logEvent(env, space, "billing.cancel_email", mail);
          }
        }
        return json(r);
      } catch (e) {
        return json({ error: (e && e.message) || "could not cancel" }, 502);
      }
    }
    if (path === "/billing/resume" && request.method === "POST") {
      if (!session) return json({ error: "sign in first" }, 401);
      if (!env.STRIPE_KEY) return json({ error: "billing is not enabled on this instance" }, 400);
      try {
        const r = await resumeSubscription(env, charge, space);
        if (r.ok) {
          await logEvent(env, space, "billing.resumed", {});
          if (emailConfigured(env)) {
            const mail = await sendResumeEmail(env, { to: r.email, space, origin: url.origin, current_period_end: r.current_period_end });
            await logEvent(env, space, "billing.resume_email", mail);
          }
        }
        return json(r);
      } catch (e) {
        return json({ error: (e && e.message) || "could not resume" }, 502);
      }
    }

    // ── THE DOOR (server-side). Everything past this point is the wallet itself — reads and writes.
    // An unsubscribed browser session is turned away here, not by the client. /whoami, the app shell,
    // and /billing/* are all handled above this line, so the subscribe flow still works; nothing
    // below is reachable without an active subscription. (subscribed is always true for self-host /
    // agents / owner-token callers, so this only ever gates a paying SaaS tenant's browser session.)
    { const g = requireSub(); if (g) return g; }

    // ── agents: mint / list / revoke scoped bearers (mint + revoke are owner acts, step-up gated) ──
    if (path === "/agents" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      const s = await stepIfSession("agent.mint");
      if (s) return s;
      const minted = await mintAgentBearer(env, space, { label: body.label, ttl_days: body.ttl_days });
      await logEvent(env, space, "agent.mint", { id: minted.id, label: minted.label, expires_at: minted.expires_at });
      return json({ ...minted, note: "This token is shown ONCE. Store it now; it cannot be recovered." });
    }
    if (path === "/agents" && request.method === "GET") {
      return json({ agents: await listAgents(env, space) });
    }
    {
      const am = path.match(/^\/agents\/([^/]+)$/);
      if (am && request.method === "DELETE") {
        if (!human) return json({ error: HUMAN_REQUIRED }, 403);
        const s = await stepIfSession("agent.revoke");
        if (s) return s;
        const r = await revokeAgent(env, space, am[1]);
        if (r.error) return json(r, 404);
        await logEvent(env, space, "agent.revoke", { id: am[1] });
        return json(r);
      }
    }

    // ── push: the owner's installed wallet subscribes so it buzzes when an agent requests a card ──
    if (path === "/push/key" && request.method === "GET") {
      return json({ key: await vapidPublicKey(env) });
    }
    if (path === "/push/subscribe" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      try {
        return json(await addSubscription(env, space, body.subscription || body));
      } catch (e) {
        return json({ error: e.message || "invalid subscription" }, 400);
      }
    }
    if (path === "/push/unsubscribe" && request.method === "POST") {
      await removeSubscription(env, space, body.endpoint);
      return json({ ok: true });
    }

    // ── list secret NAMES (never values) so the app can show what's stored + pick one for a card ──
    if (path === "/secrets" && request.method === "GET") {
      const prefix = K(space, "secret", "");
      const list = await env.VAULT.list({ prefix });
      return json({ secrets: list.keys.map((k) => k.name.slice(prefix.length)) });
    }

    // ── store a secret (owner only — seeding a real key into the vault is a human act) ──
    if (path === "/secrets" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      const s = await stepIfSession("secret.store");
      if (s) return s;
      if (!body.name) return json({ error: "name required" }, 400);
      let sealed;
      if (await splitMode(env, space)) {
        // The control plane must NEVER receive a plaintext key. The browser seals at the customer's
        // own lockbox (via /lastmile/seal-ticket) and posts back ONLY ciphertext. Reject any
        // plaintext value outright.
        if (body.value != null) return json({ error: "seal the value at your lockbox and POST { name, sealed }, never a plaintext value" }, 400);
        if (!body.sealed || typeof body.sealed !== "object" || typeof body.sealed.ct !== "string" || typeof body.sealed.iv !== "string") {
          return json({ error: "sealed ciphertext { iv, ct } required — seal it at your lockbox first" }, 400);
        }
        const ref = await env.VAULT.get(K(space, "dek", "active"));
        sealed = { iv: body.sealed.iv, ct: body.sealed.ct };
        if (ref) sealed.keyRef = ref; // tag with the DEK that opens it
      } else {
        // No lockbox connected and no MASTER_KEY on this worker: there's nowhere to seal a key.
        // Tell the customer to connect their lockbox first.
        if (!env.MASTER_KEY) return json({ error: "connect your lockbox first (Lockbox → Connect) — there's nowhere to seal a key yet" }, 409);
        if (!body.value) return json({ error: "name and value required" }, 400);
        sealed = await encrypt(env, space, String(body.value));
      }
      await env.VAULT.put(K(space, "secret", body.name), JSON.stringify(sealed));
      await logEvent(env, space, "secret.store", { name: body.name }); // name only — never the value
      return json({ ok: true, name: body.name });
    }

    // ── rotate this space's vault key (owner only): mint a new DEK + re-seal every secret. The
    // MASTER_KEY (sovereign root) is untouched, so this can never lock the owner out, and an
    // agent token can never trigger it. The owner generates; only the owner commits. ──
    if (path === "/rotate" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      const s = await stepIfSession("vault.rotate");
      if (s) return s;
      let res;
      if (await splitMode(env, space)) {
        // gather every sealed secret + the current active wrapped DEK, hand them to the customer's
        // lockbox to re-seal under a fresh DEK, then persist what comes back. Plaintext stays there.
        const secrets = [];
        let cursor;
        const prefix = K(space, "secret", "");
        do {
          const page = await env.VAULT.list({ prefix, cursor });
          for (const k of page.keys) {
            const raw = await env.VAULT.get(k.name);
            if (raw) secrets.push({ name: k.name.slice(prefix.length), sealed: JSON.parse(raw) });
          }
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
        const out = await callLastMile(env, space, "/rotate", { secrets, dek: await activeWrappedDEK(env, space) });
        await env.VAULT.put(K(space, "dek", out.dek.ref), JSON.stringify({ ...out.dek, created: new Date().toISOString() }));
        await env.VAULT.put(K(space, "dek", "active"), out.dek.ref);
        for (const s of out.secrets) await env.VAULT.put(K(space, "secret", s.name), JSON.stringify(s.sealed));
        res = { ref: out.dek.ref, rotated: out.secrets.length };
      } else {
        res = await rotateDataKey(env, space);
      }
      await logEvent(env, space, "vault.rotate", { ref: res.ref, rotated: res.rotated });
      return json({ ok: true, ...res });
    }

    // ── connect THIS space to its OWN lockbox worker (on the customer's Cloudflare). Owner-gated.
    // We store only the URL + relay token to reach it — never a customer key. Once connected, the
    // space is routed to that lockbox and the control plane holds only ciphertext. ──
    if (path === "/lastmile/connect" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      const s = await stepIfSession("lastmile.connect");
      if (s) return s;
      let h;
      try { h = new URL(String(body.url || "")); } catch { return json({ error: "enter your lockbox worker's https URL" }, 400); }
      if (h.protocol !== "https:") return json({ error: "lockbox url must be https" }, 400);
      if (ssrfBlocked(h.host)) return json({ error: "lockbox host not allowed" }, 400);
      const base = h.origin + h.pathname.replace(/\/+$/, "");
      // Claim the relay token SERVER-TO-SERVER: the lockbox self-minted it and hands it out ONCE
      // via /bootstrap. The control plane grabs it directly, so the customer (and their agent) never
      // copies a token — they only paste the lockbox's URL. (First-call-wins: deploy, then connect.)
      let creds;
      try {
        const r = await fetch(base + "/bootstrap", { headers: { "User-Agent": "fort-card-control-plane" } });
        creds = await r.json().catch(() => ({}));
        if (!r.ok || !creds.last_mile_key) {
          const already = creds && creds.error && /already claimed/i.test(creds.error);
          return json({ error: already ? "that lockbox's link was already claimed — deploy a fresh lockbox and connect again" : "couldn't claim the lockbox at that URL (" + r.status + ")" }, 400);
        }
      } catch {
        return json({ error: "couldn't reach that lockbox URL — check it's deployed and correct" }, 400);
      }
      const url = String(creds.last_mile_url || base).replace(/\/+$/, "");
      await env.VAULT.put(K(space, "lastmile", "config"), JSON.stringify({ url, key: String(creds.last_mile_key) }));
      await logEvent(env, space, "lastmile.connect", { url }); // url only — never the token
      return json({ ok: true, connected: true, url });
    }
    // Mint a one-shot, short-TTL ticket so the customer's BROWSER can seal a value at their own
    // lockbox directly — the control plane never receives the plaintext. Owner-gated. Returns the
    // lockbox URL + the active wrapped DEK (ciphertext, safe to expose) for the browser to use.
    if (path === "/lastmile/seal-ticket" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      const s = await stepIfSession("lastmile.seal");
      if (s) return s;
      const cfg = await lastMileConfig(env, space);
      if (!cfg) return json({ error: "no lockbox connected for this space — connect one first" }, 409);
      const ticket = await mintSealTicket(cfg.key);
      return json({ url: cfg.url, ticket, dek: await activeWrappedDEK(env, space) });
    }
    if (path === "/lastmile/status" && request.method === "GET") {
      const cfg = await lastMileConfig(env, space);
      const pendingRaw = await env.VAULT.get(K(space, "lastmile", "pending"));
      const pending = pendingRaw ? (() => { try { return JSON.parse(pendingRaw).url; } catch { return null; } })() : null;
      return json({ connected: !!cfg, url: cfg ? cfg.url : null, custodial: !cfg, pending });
    }
    // ── claim-code phone-home onboarding (kills the URL paste) ──
    // Mint a one-time, short-TTL claim code. Owner-gated. The wallet shows it next to the Deploy
    // button; the customer types it (plus the control-plane URL) on Cloudflare's deploy screen.
    if (path === "/lastmile/claim-code" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      // No passkey step here on purpose: minting a code is harmless (it lands PENDING and the
      // approve tap below is the real gate), so onboarding stays smooth.
      const code = await mintClaimCode(env, space);
      await logEvent(env, space, "lastmile.claim_minted", {}); // never log the code
      // The lockbox also needs to know WHERE to phone home — surface this worker's own origin so the
      // wallet can show it as the second value to paste. (Public; safe to expose.)
      return json({ code, ttl_minutes: 30, control_plane_url: url.origin });
    }
    // Approve a pending phone-home → promote it to the space's active lockbox config. Owner-gated,
    // passkey step — this is the gate that a leaked claim code can never pass.
    if (path === "/lastmile/pending/approve" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      const s = await stepIfSession("lastmile.approve");
      if (s) return s;
      const raw = await env.VAULT.get(K(space, "lastmile", "pending"));
      if (!raw) return json({ error: "no lockbox is waiting to connect" }, 409);
      const p = JSON.parse(raw);
      await env.VAULT.put(K(space, "lastmile", "config"), JSON.stringify({ url: p.url, key: p.key }));
      await env.VAULT.delete(K(space, "lastmile", "pending"));
      await logEvent(env, space, "lastmile.connect", { url: p.url, via: "phone-home" }); // url only
      return json({ ok: true, connected: true, url: p.url });
    }
    // Reject / clear a pending phone-home (didn't recognize it, or changing course). Owner-gated.
    if (path === "/lastmile/pending/reject" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      const s = await stepIfSession("lastmile.reject");
      if (s) return s;
      await env.VAULT.delete(K(space, "lastmile", "pending"));
      await logEvent(env, space, "lastmile.pending_reject", {});
      return json({ ok: true });
    }
    // ── CONNECT CLOUDFLARE (one-tap) — start: PKCE + redirect the owner to Cloudflare's consent.
    // Owner-gated (human + subscribed). No passkey step: this only STARTS consent — the sensitive
    // write happens in the callback, and it's a top-level browser navigation, not an API call. ──
    if (path === "/cloudflare/connect" && request.method === "GET") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      { const g = requireSub(); if (g) return g; }
      if (!env.CF_OAUTH_CLIENT_ID) return json({ error: "Cloudflare connect isn't configured yet (CF_OAUTH_CLIENT_ID unset)" }, 503);
      // Fail GRACEFULLY: discovery hits an external URL that may be wrong/unreachable. A throw here
      // would crash the whole worker (1101) for a logged-in owner. Catch it → bounce back to /app
      // with an error flag the PWA can toast, instead of taking the wallet down.
      try {
        const { authorization_endpoint } = await cf.discover(env);
        const { verifier, challenge } = await cf.generatePkce();
        const state = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
        await env.VAULT.put("cfstate:" + state, JSON.stringify({ space, verifier, exp: Date.now() + 600000 }), { expirationTtl: 600 });
        const authorizeUrl = cf.buildAuthorizeUrl({
          authorization_endpoint,
          clientId: env.CF_OAUTH_CLIENT_ID,
          redirectUri: url.origin + "/cloudflare/callback",
          scope: env.CF_OAUTH_SCOPES || cf.DEFAULT_SCOPES,
          state, challenge,
        });
        return Response.redirect(authorizeUrl, 302);
      } catch (e) {
        return Response.redirect(url.origin + "/app?cloudflare=error&reason=" + encodeURIComponent((e && e.message) || "connect_unavailable"), 302);
      }
    }
    // ── CONNECT CLOUDFLARE — finish: exchange the code, then drive Cloudflare's API to create the
    // KV + deploy the lockbox into the customer's own account, claim its relay token, store config.
    // The `state` (unguessable, space-bound, one-time) is the CSRF + space binding. ──
    if (path === "/cloudflare/callback" && request.method === "GET") {
      const back = (q) => Response.redirect(url.origin + "/app?" + q, 302);
      const state = url.searchParams.get("state") || "";
      const code = url.searchParams.get("code") || "";
      if (url.searchParams.get("error")) return back("cloudflare=error&reason=" + encodeURIComponent(url.searchParams.get("error")));
      const raw = state ? await env.VAULT.get("cfstate:" + state) : null;
      if (!raw) return back("cloudflare=error&reason=bad_state");
      await env.VAULT.delete("cfstate:" + state); // one-time
      const st = JSON.parse(raw);
      if (!code || st.exp < Date.now()) return back("cloudflare=error&reason=expired");
      const ps = st.space;
      try {
        const { token_endpoint } = await cf.discover(env);
        const tok = await cf.exchangeCode({
          token_endpoint, clientId: env.CF_OAUTH_CLIENT_ID,
          redirectUri: url.origin + "/cloudflare/callback", code, verifier: st.verifier,
        });
        const accountId = await cf.firstAccountId(tok.access_token);
        const source = await cf.fetchLockboxSource(env);
        const scriptName = "fort-card-lockbox";
        const kvId = await cf.createKvNamespace(tok.access_token, accountId, scriptName);
        await cf.uploadLockbox(tok.access_token, accountId, scriptName, source, kvId);
        const lockboxUrl = await cf.enableWorkersDev(tok.access_token, accountId, scriptName);
        // Claim the relay token from the lockbox we just deployed (server-to-server /bootstrap),
        // retrying briefly while the new worker propagates. We never hold its MASTER_KEY.
        let key = null;
        for (let i = 0; i < 6 && !key; i++) {
          try {
            const r = await fetch(lockboxUrl + "/bootstrap", { headers: { "User-Agent": "fort-card-control-plane" } });
            const c = await r.json().catch(() => ({}));
            if (r.ok && c.last_mile_key) key = String(c.last_mile_key);
          } catch {}
          if (!key) await new Promise((res) => setTimeout(res, 1500));
        }
        if (!key) throw new Error("deployed the lockbox but couldn't claim its connection yet — open the wallet and retry connect");
        await env.VAULT.put(K(ps, "lastmile", "config"), JSON.stringify({ url: lockboxUrl, key }));
        await env.VAULT.delete(K(ps, "lastmile", "pending"));
        await logEvent(env, ps, "lastmile.connect", { url: lockboxUrl, via: "cloudflare-oauth" }); // url only
        return back("cloudflare=connected");
      } catch (e) {
        await logEvent(env, ps, "lastmile.cloudflare_error", { error: (e && e.message) || "failed" });
        return back("cloudflare=error&reason=" + encodeURIComponent((e && e.message) || "failed"));
      }
    }
    if (path === "/lastmile/disconnect" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      const s = await stepIfSession("lastmile.disconnect");
      if (s) return s;
      await env.VAULT.delete(K(space, "lastmile", "config"));
      await logEvent(env, space, "lastmile.disconnect", {});
      return json({ ok: true, connected: false });
    }

    // ── issue a card (owner → active; agent → pending, inert until the owner approves) ──
    if (path === "/cards" && request.method === "POST") {
      if (!body.name || !body.secret || !Array.isArray(body.allowed_hosts) || body.allowed_hosts.length === 0) {
        return json({ error: "name, secret, and a non-empty allowed_hosts array are required" }, 400);
      }
      { const g = requireSub(); if (g) return g; }
      const pending = !human; // an agent can ask, but never mint its own live allowance
      if (!pending) {
        // a human issuing an ACTIVE card is an owner act — fresh tap (sessions only).
        const s = await stepIfSession("card.issue");
        if (s) return s;
      }
      const id = "card_" + crypto.randomUUID().slice(0, 8);
      const card = {
        id,
        name: body.name,
        secret: body.secret,
        holder: body.holder || null,
        allowed_hosts: body.allowed_hosts.map(String),
        header: body.header || "Authorization",
        header_prefix: body.header_prefix ?? "Bearer ",
        limit: typeof body.limit === "number" ? body.limit : null,
        used: 0,
        expires_at: body.expires_at || null,
        frozen: pending, // pending cards are inert until approved
        pending,
        // the wake target: where the requesting agent is working + listening (its own repo/PR).
        // On approval the wallet posts a comment there so the subscribed agent resumes at once.
        wake: body.wake && body.wake.repo && body.wake.pr ? { repo: String(body.wake.repo), pr: Number(body.wake.pr) } : null,
        created: new Date().toISOString(),
      };
      await cardOp(env, space, id, "init", { card });
      await registerCard(env, space, id);
      await logEvent(env, space, pending ? "card.request" : "card.issue", {
        id, name: card.name, secret: card.secret, holder: card.holder, allowed_hosts: card.allowed_hosts, limit: card.limit, pending,
      });
      if (pending) await notifyCardRequest(env, space, card);
      return json(card);
    }

    // ── list cards (the statement's subjects — never the underlying key). Live state comes from
    // each card's DO; the KV index just enumerates which cards exist in this space. ──
    if (path === "/cards" && request.method === "GET") {
      const cards = (await listCardStates(env, space)).map((c) => ({
        id: c.id, name: c.name, secret: c.secret, holder: c.holder ?? null, allowed_hosts: c.allowed_hosts,
        limit: c.limit, used: c.used, remaining: c.limit != null ? Math.max(0, c.limit - c.used) : null,
        expires_at: c.expires_at, frozen: c.frozen, pending: c.pending || false,
      }));
      return json({ cards });
    }

    // ── the statement: read the append-only audit ledger (newest first) ──
    if (path === "/events" && request.method === "GET") {
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "100", 10) || 100, 1000);
      const list = await env.VAULT.list({ prefix: K(space, "event", "") });
      const keys = list.keys.map((k) => k.name).sort().reverse().slice(0, limit);
      const events = [];
      for (const name of keys) {
        const raw = await env.VAULT.get(name);
        if (raw) events.push(JSON.parse(raw));
      }
      return json({ events });
    }

    // ── export the WHOLE statement as a downloadable file (it's the owner's data — one tap, no
    // friction). The UI only ever loads the last few events for speed; this is the full ledger,
    // paged through with the cursor so it's complete regardless of size. ──
    if (path === "/events/export" && request.method === "GET") {
      const events = [];
      let cursor;
      do {
        const page = await env.VAULT.list({ prefix: K(space, "event", ""), cursor });
        for (const k of page.keys) {
          const raw = await env.VAULT.get(k.name);
          if (raw) { try { events.push(JSON.parse(raw)); } catch {} }
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
      events.reverse(); // newest first
      const fname = "fort-card-log-" + new Date().toISOString().slice(0, 10) + ".json";
      return new Response(JSON.stringify({ space, exported_at: new Date().toISOString(), count: events.length, events }, null, 2), {
        headers: { "Content-Type": "application/json", "Content-Disposition": 'attachment; filename="' + fname + '"' },
      });
    }

    // ── DATA EXPORT (GDPR Arts 15 & 20 — access + portability). Everything we hold for this space in
    // one JSON: the full statement, card configs, the NAMES of stored secrets (never the values — the
    // wallet itself can't read them), billing summary. Human + unlock; NOT subscription-gated — the
    // right to your own data doesn't depend on an active plan. ──
    if (path === "/export" && request.method === "GET") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      // Same gate as using the app, and then some: a browser human must present a FRESH passkey
      // step-up (fingerprint/Face ID) scoped to this action. Self-host API-token callers (no
      // session) are trusted, mirroring the rest of the wallet.
      if (session) { const g = await requireStepUp(env, request, space, "data.export"); if (g) return g; }
      return json(await buildExport(env, space));
    }

    // ── ERASE EVERYTHING (GDPR Art 17 — right to erasure, on demand, BEFORE any lapse timer). The UI
    // does the two-step confirm; here we require a human + unlock + an explicit { confirm: "DELETE" }.
    // Cancels the Stripe subscription first (best-effort, so there's no future charge for data that's
    // gone), then wipes the whole space. Irreversible. NOT subscription-gated — you can always delete
    // your own data. ──
    if (path === "/erase" && request.method === "POST") {
      if (!human) return json({ error: HUMAN_REQUIRED }, 403);
      // Destructive + irreversible: a browser human must present a FRESH passkey step-up
      // (fingerprint/Face ID) for this exact action — the session unlock alone is not enough.
      // Self-host API-token callers (no session) are trusted, mirroring the rest of the wallet.
      if (session) { const g = await requireStepUp(env, request, space, "data.erase"); if (g) return g; }
      if (body.confirm !== "DELETE") return json({ error: "confirmation required", code: "confirm_required" }, 400);
      const deleted = await eraseSpace(env, space, billingOn && subscribed ? charge : null);
      return json({ erased: true, space, keys_deleted: deleted });
    }

    // ── /cards/:id  (use · freeze · revoke) — live state lives in the card's Durable Object ──
    const m = path.match(/^\/cards\/([^/]+)(\/use|\/freeze)?$/);
    if (m) {
      const id = m[1];
      const sub = m[2];
      await migrateSpaceCards(env, space); // ensure a legacy card is in its DO before freeze/revoke/use

      if (sub === "/use" && request.method === "POST") {
        { const g = requireSub(); if (g) return g; }
        // The DO atomically fences (pending/frozen/revoked/expired/cap/host) + counts the spend, then
        // chargeCard injects the key server-side and returns only the response. A decline is still a
        // line on the statement (chargeCard logs it).
        return json(await chargeCard(env, space, id, { url: body.url, method: body.method, headers: body.headers, body: body.body }));
      }

      if (sub === "/freeze" && request.method === "POST") {
        const frozen = !!body.frozen;
        // Freezing (kill switch) is a de-escalation any holder may do. UNFREEZING re-authorizes
        // a card — owner only — and unfreezing a PENDING card is how the owner approves it.
        if (!frozen && !human) return json({ error: HUMAN_REQUIRED }, 403);
        if (!frozen) {
          const g = requireSub(); if (g) return g;
          const s = await stepIfSession("card.approve");
          if (s) return s;
        }
        const before = await cardOp(env, space, id, "status");
        if (!before) return json({ error: "no such card" }, 404);
        const approved = !frozen && !!before.pending;
        const card = await cardOp(env, space, id, "freeze", { frozen }); // atomic in the DO
        await logEvent(env, space, frozen ? "card.freeze" : approved ? "card.approve" : "card.unfreeze", { id });
        if (approved) await wakeRequester(env, space, card); // write back to the agent's branch so it resumes
        return json({ id, frozen: card.frozen, pending: card.pending || false });
      }

      if (!sub && request.method === "DELETE") {
        await cardOp(env, space, id, "revoke"); // the DO drops the state; a spend can't bring it back
        await unregisterCard(env, space, id);
        await logEvent(env, space, "card.revoke", { id });
        return json({ revoked: id });
      }
    }

    return json({ error: "not found" }, 404);
  },

  // Cloudflare Cron Trigger → the lapse-lifecycle sweep (grace emails, reminders, and — only when
  // PURGE_ENABLED is set — the 30-day purge). Schedule lives in wrangler.toml ([triggers] crons).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runLifecycle(env));
  },
};
