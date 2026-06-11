#!/usr/bin/env node
// Fort Card — a 2-minute demo of "issue credentials like CREDIT CARDS, not keys."
//
// The idea: a robot/agent should NEVER hold your real API key. It holds a CARD — a useless
// pointer that's locked to ONE website, capped to N uses, and freezable with one tap. The
// VAULT holds the real key and makes the call on the card's behalf, returning only the
// result. Steal the card → you get nothing. Steal the key → you're wiped out. We use cards.
//
// Runs on plain Node 18+ (no install, no Cloudflare account). Bring your own API token.
//
//   node card-demo.mjs <API_TOKEN> [ALLOWED_HOST] [TEST_URL] [HEADER_SCHEME]
//
// Default example uses a GitHub token:
//   node card-demo.mjs ghp_yourtoken api.github.com https://api.github.com/user token
//   (classic GitHub PATs use the "token" scheme; most other APIs use "Bearer")

import { webcrypto as crypto } from "node:crypto";

// ───────────────────────── THE VAULT (holds real keys, encrypted) ─────────────────────────
// The real key goes in here and never comes back out. Only the vault can read it.
const MASTER = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const VAULT = new Map();
async function storeSecret(name, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, MASTER, new TextEncoder().encode(value));
  VAULT.set(name, { iv, ct });
}
async function readSecretInternal(name) {
  // INTERNAL to the vault — never returned to a caller, never logged.
  const s = VAULT.get(name);
  if (!s) throw new Error("no such secret");
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: s.iv }, MASTER, s.ct));
}

// ───────────────────────── THE CARDS (pointers at secrets, with limits) ─────────────────────────
const CARDS = new Map();
function issueCard({ name, secret, allowedHosts, limit, headerScheme = "Bearer" }) {
  const id = "card_" + crypto.randomUUID().slice(0, 8);
  CARDS.set(id, { id, name, secret, allowedHosts, limit, used: 0, frozen: false, headerScheme });
  return id;
}
function freezeCard(id, frozen = true) { CARDS.get(id).frozen = frozen; }

// ───────────────────────── THE AUTHORIZATION (ISO-8583 in spirit) ─────────────────────────
// Present a card + a request. Check the rules. If OK, the VAULT injects the real key and
// makes the call — and returns ONLY the response. The caller never sees the key.
async function useCard(id, request) {
  const c = CARDS.get(id);
  if (!c) return { authorized: false, decline: "no such card" };
  if (c.frozen) return { authorized: false, decline: "card frozen" };
  if (c.limit != null && c.used >= c.limit) return { authorized: false, decline: "limit reached" };
  let host;
  try { host = new URL(request.url).host; } catch { return { authorized: false, decline: "bad url" }; }
  if (!c.allowedHosts.includes(host)) return { authorized: false, decline: `host ${host} not allowed for this card` };

  const key = await readSecretInternal(c.secret); // the only place the key becomes real
  const resp = await fetch(request.url, {
    method: request.method || "GET",
    headers: { Authorization: `${c.headerScheme} ${key}`, "User-Agent": "fort-card-demo", ...(request.headers || {}) },
  });
  const text = await resp.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  c.used++;
  return { authorized: true, status: resp.status, body, card: { id, used: c.used, remaining: c.limit != null ? c.limit - c.used : null } };
}

// ───────────────────────── THE DEMO ─────────────────────────
const [, , TOKEN, ALLOWED_HOST = "api.github.com", TEST_URL = "https://api.github.com/user", SCHEME = "Bearer"] = process.argv;
if (!TOKEN) {
  console.error(
    "Usage: node card-demo.mjs <API_TOKEN> [ALLOWED_HOST] [TEST_URL] [HEADER_SCHEME]\n" +
      "GitHub example: node card-demo.mjs ghp_xxx api.github.com https://api.github.com/user token",
  );
  process.exit(1);
}
const p = (s) => console.log(s);

p("\n🔐 1. Lock the real key in the vault (encrypted). Nothing outside the vault ever sees it again.");
await storeSecret("my-key", TOKEN);

p(`💳 2. Issue a CARD — locked to ${ALLOWED_HOST}, max 3 uses, freezable. THIS is all the robot gets:`);
const card = issueCard({ name: "demo card", secret: "my-key", allowedHosts: [ALLOWED_HOST], limit: 3, headerScheme: SCHEME });
p(`      ${card}   ← hand this to the agent, never the key`);

p("\n🤖 3. The agent (holding ONLY the card id) makes a real authenticated call:");
const r1 = await useCard(card, { url: TEST_URL });
p(`      → authorized:${r1.authorized}  status:${r1.status}  ${JSON.stringify(r1.card)}`);
p(`      real response (trimmed): ${JSON.stringify(r1.body).slice(0, 200)}`);

p("\n🚫 4. The agent tries to send your key somewhere ELSE (theft / exfil attempt):");
p(`      → ${JSON.stringify(await useCard(card, { url: "https://evil.example.com/steal" }))}`);

p("\n🧊 5. You FREEZE the card; the agent tries again:");
freezeCard(card, true);
p(`      → ${JSON.stringify(await useCard(card, { url: TEST_URL }))}`);

p("\n✅ The agent made a real call and NEVER saw the key. Theft and the frozen card were both declined.");
p("   That's a credit card, not a key. The whole point in one screen.\n");
