# Sub-processors

The third parties a Fort Card deployment may rely on to process data. Optional ones are only engaged
when the operator turns that feature on. Each operator should execute (accept) the relevant
sub-processor's standard Data Processing Agreement and confirm its transfer safeguards.

| Sub-processor | Purpose | Data it sees | Engaged |
|---|---|---|---|
| **Cloudflare** (Workers + KV) | Runs the worker; stores the vault (KV) | All stored data — but stored secrets are **encrypted**; Cloudflare holds ciphertext, not plaintext keys | Always (the platform) |
| **GitHub** | OAuth sign-in; the wake-back App | Your GitHub login/id; (App) PR comments to resume agents | When OAuth/App login is configured |
| **Stripe** | Subscription billing | Payment details, billing email, subscription status | Only when billing is enabled (`STRIPE_KEY` set) |
| **Resend** | Transactional email (welcome, cancel, lapse, reminder) | Recipient email + message content | Only when email is enabled (`RESEND_KEY` set) |

## Notes
- **The plaintext of your stored secrets is never sent to any sub-processor.** Keys are sealed; the
  worker injects them into the upstream request server-side and only relays the response.
- A pure **self-host** deployment with billing and email off engages only Cloudflare (and GitHub if
  OAuth login is used).
- **International transfers:** confirm the mechanism for each processor (e.g. SCCs, EU–US Data Privacy
  Framework, Cloudflare's EU data-localization options) for your jurisdiction.

_Operators: keep this list current; notify users before adding a sub-processor that handles their data._
