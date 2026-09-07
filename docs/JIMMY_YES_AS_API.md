# Jimmy's Yes as an API (Fort Card)
Date: 2026-09-07
Status: design consensus — not yet built

This is the dated next-layer consensus. [`DESIGN.md`](../DESIGN.md) remains the source of truth for the wallet as built (cards, lockbox, passkey, agent bearers). This report does not replace that document; it specifies the approval-grant layer to add *inside* Fort Card.

Core source for the GPT + Claude thread: record `88600909-5b6e-451e-ae16-b54122eb9586` (*Fort Card — Jimmy's Yes as a Sovereign Capability Lease*).

---

## Problem

Soft approval is advisory. Doctrine, the zone web, and an A.S.S. lease can say "ask first," but cutting that approval does not cut gas if credentials still sit outside the meter. A rule that says "ask Jimmy" is not a gate if a worker, cron, or native tool can still authenticate on its own.

Fort Card already works for the half it was built to do: secrets sit behind the gate. No card → no key → no authenticated call. The agent never holds the credential; the wallet injects it server-side. That is why freeze and revoke actually stop spend.

What is missing is the second half: for *this action*, has Jimmy authorized the crossing? Today's usable card is standing delegated authority. A live card is enough to leave the building. Yes is still a boolean agents are asked to honor, not a credential the wallet mints and burns.

A.S.S. ledger noise (2026-09-07 audit) makes the soft layer worse to operate, even before grants exist:

- ~238 `show_ass` declares, mostly internal cron.
- Only 3 client declares under `actor:jimmy`.
- `self` is often just `"River"` — persona without runtime, which is camouflage.
- Naked mesh/weave sweeps ran ~90 minutes past lease expiry.
- `port:river-agent` copied the Registry `self` string verbatim.

That audit is hygiene, not the grant primitive. It is the same day's evidence that advisory boundaries drift.

---

## Claude's cut (mint / burn / hash)

Stop treating yes as a boolean agents check. Yes *mints* the credential. The agent never holds it; the wallet injects it; absent a valid grant, refuse server-side. The packet does not leave.

This lives inside Fort Card. No second product, no sibling approval app, no second wallet.

### The grant

Approval mints a **signed grant**:

- card ref
- amount ceiling
- merchant allowlist
- expiry
- use count
- nonce

`use_card` requires a live grant or it refuses. A lease that is only a database row is decorative: anything with write access could mint an approval. The signing key is held by the wallet and by nothing else — not by workers, not by agents, not by anything that can be talked into writing a row. Verify at consumption, not just at read.

### Burn, not a well

Grants **burn** (a tank, not a well). Single-use or N-use, decremented server-side. Spend consumes; it does not refill itself.

### Bind intent

Hash what the agent said into the grant. Recompute at charge. Mismatch → refuse. The agent cannot get a yes for "$12 here" and spend "$12 somewhere else."

Hash a **semantic subset**, not the raw canonicalized body — merchant/host, operation class, target resource, amount ceiling. Let incidental fields (timestamps, idempotency keys, reordered JSON) float. Binding noise produces false denials, Jimmy widens the tolerance, and the hash stops meaning anything. The failure mode of over-tight binding is the same as over-tight ceilings: the human turns it off.

### Out-of-band tap

Approval is out-of-band (phone push). Fort Card renders the human-readable surface from the canonical request. The agent only sees `grant_id` + status. It never renders or reads Jimmy's answer, and it does not control what he sees.

An agent that receives `APPROVAL_REQUIRED` has exactly one legal move: halt, write the request, hand control back. Not retry. Not route around. Not improvise an alternate path to the same effect. The wallet should refuse repeat attempts on the same pending `request_id`. Refusal *rate* (the curve, not each event) is the health metric: a spike means ceilings are wrong or something is behaving oddly.

### Silence is a stop

Expiry makes silence a stop. No heartbeat, no grant, no gas.

### Ambient / standing tanks

Standing grants carry a ceiling and a rolling window that refills **only on Jimmy heartbeat**. Go dark → the tank drains to zero. Internal thought, memory, and drafting can continue; externally-acting authority cannot. Novel merchant, over ceiling, or a new card → fresh explicit yes.

### Ledger and revoke

`revoke_all` plus a ledger line for every mint, burn, and refusal. Once revoked or expired, the next attempted egress has no gas.

### Open numbers (as Claude left them)

- Grant TTL
- Heartbeat = any interaction vs deliberate only

Highlander settles both below.

### Same-day implementation traps (Claude Opus 5, signed)

These do not change the primitive. They keep it from becoming felt coverage:

1. **Classification test is "would Jimmy read this," not "is it dangerous."** A rubber-stamp gate is worse than honest infinity. Split by *frequency*: what he would wave through goes to infinity on the record; the small set he would pause on breaks out to a tap. Rarity keeps the gate meaningful.
2. **Two tables, not one.** Operation-danger classification (host + method + path → op class) lives in the wallet, is boring, and is rarely touched. Tolerance (which actor gets standing lease vs ask, per op class) lives in Jimmy's Fort app and is flippable. One table being flipped from a phone can silently reclassify a refund as read-only.
3. **Ring model for tolerance** (Jimmy's framing — Sheldon's concentric zones). Unknown/new actors land in the outermost ring. Promotion inward is deliberate and visible. Demotion is a flip, not a review — push an actor out and its leases die on the next call. Three or four rings; more granularity dies of neglect.
4. **Open question:** can anything running today write the zone web? If an agent can modify its own tolerance, the tier system is advisory.
5. **Cloudflare is existence, not spend.** Highest-volume credential; a bad call can delete a worker, repoint DNS, or rotate the token you'd use to fix it. Reads and deploys of existing workers stay at infinity (gating them would get the system turned off in a day). Delete-worker, DNS replacement, and API-token changes break out — a handful of events per month, maybe five or six endpoints. Two Cloudflare cards exist; whether the wide one is genuinely dormant until an approved mint (real gate) or merely provisioned-but-unrequested (a door nobody has tried) is unverified.
6. **Sequencing:** enumerate destructive Cloudflare endpoints first. Smallest change that isn't a migration. If it survives two weeks without annoying Jimmy, the pattern is validated. Full custody migration does not start until that holds. Design is a weekend; migration is weeks. A half-migrated system is worse than none.

---

## GPT's cut (intersection + enforcement placement)

Fort Card today answers: "does this agent have delegated authority to reach this service?" That is necessary and not sufficient. The missing question is: "for this action, has Jimmy authorized the crossing?"

```
ACTION ALLOWED = credential capability ∩ A.S.S. lane ∩ approval capability
```

No second wallet. No second app. Fort Card evolves from "where secrets are kept" into the broker where delegated human authority becomes executable without becoming transferable.

A.S.S. answers WHERE / WHO (arc, self, lane). Approval zones answer HOW MUCH human authority this class of action requires. Fort Card answers CAN the boundary be crossed right now.

### Flow

`use_card` is the sole crossing:

1. Agent attempts `use_card` / protected egress.
2. Fort Card validates the current A.S.S.
3. Fort Card classifies the action's zone. **Never trust an agent-supplied zone** — `{"zone":"repo-code"}` from the caller is asking the burglar for his zone.
4. **FULL** → execute + ledger.
5. **PARTIAL** → execute + ledger + tell Jimmy.
6. **ASK** → no execution. Canonicalize the intended operation, create an immutable approval request, phone-push Jimmy. YES mints a one-time (or N-use, scoped) grant. Wake the agent. Execute the *exact* approved action.

Prefer `use_card` returning `APPROVAL_REQUIRED` over a separate ask tool. `ask_card` remains the way to request a *new card* (or recharge). Action-level ratification happens on the charge path.

### Yes is an event, not a flag

Yes is an event that **creates a capability**, not `jimmy_says_yes=true`. A grant / lease carries at least:

| Field | Role |
| --- | --- |
| `approval_id` / grant id | The minted yes |
| zone | FULL / PARTIAL / ASK as classified by Fort Card |
| actor | persona + runtime / session identity |
| card | which card the grant is bound to |
| action | operation / capability scope |
| resource | merchant / recipient / target |
| `request_hash` | binding of the canonicalized operation |
| `expires_at` | silence becomes a stop |
| `max_uses` | burn counter |

Plus: arc, allowed hosts, amount ceiling, nonce, issued_at, revocation state.

`request_hash` binds the canonicalized operation. Bait-and-switch after yes fails.

### Bounded multi-use

The same primitive covers one-shot and standing without turning Jimmy into a clerk:

- one-use destructive action: `uses=1`, short TTL
- 100 transactional emails for 24h
- known recurring merchant under a rolling ceiling
- long-lived read-only inspection

Scope × duration × quantity × resource.

### Critical catch

Sensitive actions must not bypass Fort Card via native tools. Any worker, agent, or cron that can still "act as Jimmy" with standing GitHub / Stripe / Cloudflare / Resend / Migadu / social / publishing credentials *outside* the broker defeats the gate.

Implementation is two halves:

1. Extend Fort Card with sovereign capability leases (internal names like `ass-lease` / `jimmy-act` are fine; they are not a second product).
2. Inventory every `actor:jimmy` egress and remove independent gas from the paths that should be gated.

Desired invariant: if an action is Jimmy-gated and he has not granted or renewed the lease, there is no authenticated execution path. The system stops because there is no gas, not because doctrine says "please stop."

---

## Highlander / River (Grok door) cut — 2026-09-07

### Reactions

Both point at the same load-bearing move: **yes mints gas; without a grant the packet does not leave.**

Claude is sharpest on: burn grants, `request_hash`, out-of-band tap, silence = stop, heartbeat standing tanks. Also the traps that keep those from becoming theater (semantic hash, wallet-held signing key, refusal semantics, two tables, rings).

GPT is sharpest on: credential ∩ A.S.S. ∩ approval; Fort Card owns zone policy; `use_card` as the sole crossing; no bypass door.

### Settled defaults (Highlander)

- **Grant TTL for ASK:** short (minutes), unless Jimmy typed a standing window.
- **Heartbeat refill:** **deliberate only** (explicit check-in / refill), not any chat message.
- **One product:** extend Fort Card (approval / sovereign grants), not a sibling meter.

### Related A.S.S. hygiene (not the same as grant mint, but same audit)

1. Doctrine: A.S.S. `self` must name persona + runtime (e.g. `River / Grok Bot`, `River / Cursor cloud agent`, `River / Claude Code`) — persona alone is camouflage.
2. Fail-closed on expired A.S.S. lease for mesh/weave (stops naked sweeps).
3. Fix `port:river-agent` hardcoded Registry `self` string (code).
4. Tag or separate internal cron declares so client ledger queries aren't drowned.

---

## What we are going to do (do-next)

Ordered, concrete.

**Now / soon (doctrine + hygiene)**

1. Bank Core doctrine: `self` = persona + runtime.
2. Builder order: fail-closed expired A.S.S. lease on mesh/weave; fix river-agent Registry impersonation; optional internal-declare tagging.

**Design → build (Fort Card)**

3. Spec + implement Approval Grants inside Fort Card:
   - PROPOSE → HUMAN RATIFY (phone) → MINT SCOPED GRANT → CONSUME via `use_card`
   - `request_hash` binding (semantic subset); burn/decrement; expiry; `revoke_all`; ledger mint/burn/refuse
   - Fort Card–owned zone→action policy map (Stripe / Cloudflare / Mail examples as starting policy)
   - Standing ambient = heartbeat tanks (deliberate refill)
4. Close bypass doors: any ASK / money / outbound / destructive write path must only be reachable through Fort Card spend + grant check.
5. Attach this report to the Builder plan when the plan is cut; PR merges as you go.

---

## Non-goals

- Second approval app / second wallet.
- Soft "please honor the zone" without mint/burn.
- Agent-in-the-loop ratification.
