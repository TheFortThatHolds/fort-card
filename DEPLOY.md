# Deploy (managed instance)

Stand the service up **once**. After that, every client just signs in — they never deploy
anything. Keys live on Cloudflare; this repo stays generic (no instance ids, no secrets).

## One-time operator setup

1. **KV namespace** — create one and note its id:
   `npx wrangler kv namespace create VAULT`

2. **GitHub App** (identity-only, no repo permissions) — note its **Client ID** and generate a
   **client secret**. Set the callback URL to `https://<your-domain>/callback`.

3. **Worker vars + secrets** (Cloudflare dashboard → your Worker → Settings → Variables and Secrets).
   `keep_vars = true` keeps these across deploys.
   - Secrets: `MASTER_KEY` (`openssl rand -base64 32`), `GH_CLIENT_SECRET`.
   - Vars: `GH_CLIENT_ID`, `GH_CALLBACK_URL`, `WALLET_RPID`, `WALLET_ORIGIN`,
     and optionally `CORE_ORIGIN` (lets a host frame `/app` as a plugin).

4. **Repo secrets** (GitHub → Settings → Secrets and variables → Actions) so the deploy workflow can ship:
   `CLOUDFLARE_API_TOKEN` (Workers Scripts:Edit), `CLOUDFLARE_ACCOUNT_ID`, `KV_NAMESPACE_ID`.

5. **Custom domain** — point your domain at the Worker (Cloudflare → Worker → Settings → Domains & Routes).

6. **Deploy** — push to `main` (or run the **deploy** workflow). Done.

## After that

Open `/app`, sign in with GitHub, add a passkey. Every client does the same — zero deploy.
Sovereignty option: a tenant who wants host-blind keys runs their own last-mile worker
(`worker/src/last-mile.js`); see DESIGN §10.
