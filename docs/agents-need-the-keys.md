Agents Need the Keys, and the Keys Make Them the Target

Status: CONCEPT ONLY — NOT BUILT. This is a problem analysis and a design
sketch, not a product announcement. Nothing described here is shipped.
Open questions are listed at the end, not hidden.

Terms, defined before use:
- Agent: a software helper that acts on your behalf — moving money,
  touching customer data, changing real systems.
- Secret: a key, credential, or token that unlocks something valuable.
- Custodian: a gated agent whose only job is holding one piece of a split
  secret and releasing it under a rule.
- Shard: one piece of a split secret. One shard alone reveals nothing
  about the secret.
- Grant: a permission slip stating exactly what an identity may do, under
  whose authority.
- Receipt: a signed record of what was done, under what grant, by which
  identity, at what time — verifiable by a third party with a public key,
  without taking anyone's word for it.
- Kill: destroying an identity's authority, instantly.
- Fail closed: when the system cannot verify safety, it refuses rather
  than proceeding.

1. The problem

Agents need secrets to do useful work. But giving an agent the secret
makes that agent the target. The existing answers all share one weakness
shape:
- A central vault is one target. Break it, get everything.
- A hardware security module (HSM) or key management service (KMS) serves
  whoever passes the check. It logs which role called, not which agent
  asked, under what grant, for what purpose, to what end. And once a
  caller is authenticated, it serves.
- Giving a working agent the whole secret means breaching that one agent
  is a full breach.

So the reason enterprises won't deploy agents isn't that agents are
useless. It's that the agent needs the keys, and the keys make it a
target.

2. The shape of an answer

Don't give any agent the secret. Split it across several custodian
agents, so no single one holds enough to matter. Each custodian's grant
is tiny and exact: it may release its piece only to a verified request
from an authorized identity, for an authorized purpose. Every release is
receipted. Any custodian can be killed instantly. If one is killed, the
remaining custodians split the secret again into fresh pieces — and old
pieces are mathematically dead against the new split, not revoked by an
admin claim. Nobody has to trust a revocation; the maths does it.

The machinery underneath is three primitives: a permission slip, a
proof, and an off switch. Everything else in this document is those
three, applied to the problem of holding secrets.

3. The window — the moment the secret exists whole

This is the section most designs skip, and it is the one that decides
whether the rest can be trusted.

Rebuilding a secret — for a job, or to re-split it after a kill — means
the secret exists whole again somewhere, for a moment. Here is that
moment, stated plainly:
- Where: in ephemeral sealed memory, never written to disk. The
  deployment names the exact machine and its operator — an unnamed
  window is no answer.
- Who is in the room: a human authorizes it, plus the custodian agents
  releasing their pieces. All of it goes on the record.
- What the record proves, and what it does not: a receipt proves the
  rebuild happened, under what authorization, and which pieces were
  released. It does not prove nobody watched. A root-level attacker
  sitting on the reconstruction host reads sealed memory before any
  receipt exists. Receipts are detection and attribution, not prevention
  of observation.
- What would close the window instead of documenting it: reconstructing
  inside the HSM itself, so the secret is never in host memory in the
  clear. That is a direction, not a claim — feasibility against real
  HSMs is unvalidated, and it moves trust to the HSM hardware and vendor
  rather than eliminating trust. The boundary must be named either way.

If this section is wrong, the rest of the design should not be trusted.
If it holds, the rest follows.

4. The trust boundary

This design does not claim no trust. It names exactly who you trust, for
what, and what they alone can and cannot do.
- Separation means separate teams, separate credentials, separate
  approval chains — not five accounts held by one team. One team holding
  all five custodians is one trust domain wearing five hats, and that is
  not separation. That is a deployment requirement, not a suggestion.
- Default: the customer holds everything. The vendor holds zero pieces.
- Option for availability only: the vendor holds pieces that alone
  reveal nothing and can never rebuild without the customer's pieces.
  The customer holds enough to reconstruct alone, so the vendor alone
  can never reconstruct.
- Any single insider, admin, or compromised custodian holds at most one
  piece. One piece reveals nothing.

5. What fails closed

- Two custodians down: still serving. The design tolerates losing some
  custodians and still rebuilding.
- One compromised: nothing, on its own. Kill it, re-split, and the
  stolen piece is mathematically dead.
- Below the threshold: the system refuses rather than risking a bad
  rebuild. Fail-closed is the feature, not the bug.
- Through any single-custodian loss, service continues with zero
  interruption. Recovery time below the threshold is the time to restore
  a custodian and re-split, stated per deployment — it depends on the
  customer's provisioning speed, so no universal number is claimed here.

6. What's open

These are not decided, and they are not hidden:
- Default thresholds per secret class.
- Whether a denial spike triggers a human kill or an opt-in automatic
  kill.
- Whether reconstruction inside the HSM is feasible against real
  hardware.
- How separation is evidenced per customer.
- The name of the thing.

This document exists to be checked. Attack the window section first. If
it survives, the rest is worth building. If it doesn't, the design
changes here, in public, before anyone deploys it.

From the UCII project. Concept only — not part of any shipped product.
