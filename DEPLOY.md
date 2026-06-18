# Deploy (managed instance)

Stand the service up **once**. After that, every client just signs in — they never deploy
anything. You configure **one screen in GitHub** and run one workflow; the workflow does the rest
(creates the KV namespace, binds your domain, sets the vars, pushes the secrets, mints the master
key). No Cloudflare-dashboard scavenger hunt.

## 1. Make a Cloudflare API token

Cloudflare → My Profile → API Tokens → Create Token → **"Edit Cloudflare Workers"** template →
include your domain's zone → Create → copy it. (That template covers Workers scripts, KV, and the
custom domain in one.) Also note your **Account ID** (dashboard, right sidebar).

## 2. Make the GitHub App (identity-only, no repo permissions)

Note its **Client ID** (`Iv23…`); set the callback to `https://<your-domain>/callback`. The
**client secret** is generated when you need it in step 3 — no need to stash it.

## 3. Configure one screen: repo → Settings → Secrets and variables → Actions

**Secrets:**
- `CLOUDFLARE_API_TOKEN` — from step 1
- `CLOUDFLARE_ACCOUNT_ID` — from step 1
- `GH_CLIENT_SECRET` — generate a fresh client secret in the GitHub App and paste it here

**Variables:**
- `GH_CLIENT_ID` — from step 2
- `WALLET_DOMAIN` — e.g. `card.example.com` (callback / rpid / origin are derived from it)

## 4. Run it

Actions → **deploy** → Run workflow. First run creates the worker and binds the domain. This is the
**control plane** — the wallet that manages spaces, cards, approvals, billing, and the statement. It
holds only ciphertext: it never seals, opens, or injects a customer's plaintext key. That work lives
only in each customer's lockbox.

## After that

Open `https://<your-domain>/app`, sign in with GitHub, add a passkey. Every client does the same —
zero deploy. Then each customer connects their own **lockbox** — a worker on their own Cloudflare
that holds their `MASTER_KEY` and is the only thing that seals, opens, and injects their keys. Until
a space connects its lockbox, the wallet can't store or charge keys for it; see DESIGN §10.
