# 💳 Fort Card

### Issue API credentials like **credit cards**, not keys.

An API key is your bank card *with the PIN written on it* — whoever holds it can do anything it allows, forever, until you find out and kill it. That's how we hand keys to AI agents and scripts today. One leak = total wipeout.

**Fort Card treats your keys like credit cards.** The real key is locked in a vault. Instead of the key, an agent gets a **card**: a useless pointer that's locked to one host, capped to N uses, and freezable with one call. When the card is charged, the vault injects the real key *server-side* and returns only the response — **the agent never sees the key.**

- Steal a **key** → catastrophe (does everything, everywhere, forever).
- Steal a **card** → a shrug (wrong host = declined, over limit = declined, you freeze it).

> Banks solved "let someone spend on your behalf without handing over the vault" 70 years ago. This just teaches it to API keys.

---

## See it in 2 minutes (no install, no account)

The [`demo/card-demo.mjs`](demo/card-demo.mjs) file is a self-contained miniature you can run with plain Node 18+ and your own API token:

```bash
# GitHub example (any GitHub token works):
node demo/card-demo.mjs YOUR_TOKEN api.github.com https://api.github.com/user token

# OpenAI example:
node demo/card-demo.mjs sk-... api.openai.com https://api.openai.com/v1/models Bearer
```

You'll watch the key go into the vault, a card get issued (host-locked, capped), the "agent" make a **real authenticated call** with only the card, and then two **declines** — a theft attempt (wrong host) and a frozen card. Your token is held only in memory and never printed.

---

## Run your own vault (self-host)

The [`worker/`](worker) folder is a complete, single-file Cloudflare Worker — the real thing. Because it's open source, **you can audit every line and host it yourself**, so the decryption happens on infrastructure *you* control and no third party ever sees your keys.

```bash
cd worker
npx wrangler kv namespace create VAULT      # paste the id into wrangler.toml
npx wrangler secret put FORT_KEY             # owner bearer token you choose
npx wrangler secret put MASTER_KEY           # openssl rand -base64 32
npx wrangler secret put FORT_AGENT_KEY       # optional — the token you hand to agents
npx wrangler deploy
```

Then:

```bash
H='Authorization: Bearer YOUR_FORT_KEY'
BASE=https://fort-card.<your-subdomain>.workers.dev

# 1. lock a secret in the vault
curl -s -X POST $BASE/secrets -H "$H" -d '{"name":"gh","value":"ghp_xxx"}'

# 2. issue a card, locked to GitHub, max 50 uses
curl -s -X POST $BASE/cards -H "$H" \
  -d '{"name":"agent card","secret":"gh","allowed_hosts":["api.github.com"],"limit":50,"header_prefix":"token "}'

# 3. the agent charges the card — never holding the key
curl -s -X POST $BASE/cards/card_xxxx/use -H "$H" \
  -d '{"url":"https://api.github.com/user"}'

# freeze it instantly
curl -s -X POST $BASE/cards/card_xxxx/freeze -H "$H" -d '{"frozen":true}'
```

---

## The trust ladder

| Mode | Who can see the decrypted key |
|---|---|
| **Self-host** (this repo) | only you — it decrypts on infrastructure you control |
| **Hosted, open code** | the host's servers at request time — but the code is *this code*, auditable, transient in-memory, never logged. (The same trust you give Apple/Google Wallet every day.) |
| **Hosted + confidential computing** | nobody — the key decrypts inside a sealed enclave the operator can't read |

The destination service (GitHub, OpenAI, …) still receives the real key — it has to; it's the bank, and you're legitimately using it. The point isn't to hide the key from the *service*. It's to keep it out of the **agent's** hands — and out of your chat logs, your notes, your repos — where leaks actually happen.

---

## How it works

1. **Vault** — the real key goes in encrypted (AES-GCM) and never comes back out.
2. **Card** — a named pointer at the secret: locked to specific hosts, capped, freezable. This is all the agent gets.
3. **Charge** — the agent presents `card + request`; the vault checks the rules (frozen? expired? over limit? host allowed?), injects the real key server-side, makes the call, and returns only the response.
4. **Statement** — every act (issue, charge, decline, freeze, approve, revoke) is appended to an audit ledger you can read at `GET /events`. The ledger never holds a key or a secret value.

## Human-in-the-loop

A per-card limit means nothing if the holder can mint a fresh card or refill its own allowance — so **issuing** and **re-authorizing (unfreezing)** a card are *owner* acts. The worker tells human from agent by **which token** is presented:

- **`FORT_KEY`** (owner) — issues **active** cards, approves/unfreezes, stores secrets.
- **`FORT_AGENT_KEY`** (optional, the token you hand to agents) — may **request**/use/freeze/revoke. A card an agent issues is **pending**: inert until you approve it (by unfreezing it as the owner), and a `NOTIFY_WEBHOOK` POST is fired so you know to. An agent can ask for a card — it can never mint or refill its own live allowance.

If you don't set `FORT_AGENT_KEY`, only the owner token works and every card is active (the simple single-token mode). *(The hosted [Fort Memory Core](https://thefortthatholds.com) takes this further — it tells human from agent by login method and fans approvals out to email + web-push.)*

## API

| Method | Path | Body | Does | Who |
|---|---|---|---|---|
| `POST` | `/secrets` | `{name, value}` | store a secret (encrypted) | owner |
| `POST` | `/cards` | `{name, secret, allowed_hosts, holder?, limit?, expires_at?, header?, header_prefix?}` | owner → issue · agent → request (pending) | owner / agent |
| `GET` | `/cards` | — | list cards (never the key) | owner / agent |
| `GET` | `/events` | `?limit=N` | read the statement (audit ledger) | owner / agent |
| `POST` | `/cards/:id/use` | `{url, method?, headers?, body?}` | authorize + charge | owner / agent |
| `POST` | `/cards/:id/freeze` | `{frozen}` | freeze (any) / unfreeze = approve (owner) | owner / agent |
| `DELETE` | `/cards/:id` | — | revoke | owner / agent |

All routes require `Authorization: Bearer <FORT_KEY or FORT_AGENT_KEY>`.

---

## Why now

Every company on earth is handing API keys to autonomous agents right now, and quietly terrified about it. MCP is becoming the universal rail agents speak — the "ISO-8583 moment" for agent actions. Put a vault behind it and you have a card network for credentials: agents carry capped, host-locked, freezable cards instead of god-keys.

**Issue cards. Don't hand out keys.**

---

MIT licensed. Built by [The Fort That Holds](https://thefortthatholds.com). PRs and forks welcome — read the vault, run your own, make it better.
