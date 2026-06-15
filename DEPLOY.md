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

Actions → **deploy** → Run workflow. First run creates the worker, binds the domain, and mints
`MASTER_KEY`. Done.

## After that

Open `https://<your-domain>/app`, sign in with GitHub, add a passkey. Every client does the same —
zero deploy. Sovereignty option: a tenant who wants host-blind keys runs their own last-mile worker
(`worker/src/last-mile.js`); see DESIGN §10.
