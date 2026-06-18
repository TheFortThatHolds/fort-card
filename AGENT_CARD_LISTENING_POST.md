# Agent card listening post

This PR exists for one job: to be the **wake target** for Fort Card requests an agent makes via `ask_card` (`repo` + `pr`).

When an agent asks for a card, the wallet sends the owner a push to approve or deny on their phone. On the owner's tap, the wallet **posts a comment to this PR**. The agent is **subscribed to this PR's activity**, so that comment wakes it automatically — it resumes and uses (or drops) the card.

**The owner should never have to come back and say "it's approved."** If they do, the agent wired the wake target wrong (pointed it at a PR it wasn't watching). This standing post fixes that: every `ask_card` points here, and the session subscribes here.

Keep this PR open as a draft. It is infrastructure, not a change to merge.
