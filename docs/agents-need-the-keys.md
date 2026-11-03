Agents Need the Keys, and the Keys Make Them the Target

Receipts are detection and attribution, not prevention of observation.

Status: CONCEPT ONLY — NOT BUILT. This is a problem analysis and a design
sketch, not a product announcement. Nothing described here is shipped.
Open questions are listed at the end, not hidden.

This document is a checklist for evaluating any secret-splitting design,
including the one sketched here. Use it against any vendor — including
us. The checklist lifts out: run it against a different vendor, in full,
without needing anything else in this document. The body that follows is
this design's answers to it.

The checklist:
1. Which adversaries does this defend against?
2. Why can't the agent just hold the secret?
3. Is the secret actually split, or just stored in two places?
4. When does the secret exist whole, and who can watch that moment?
5. Who is trusted, for what, and what can't they do alone?
6. What happens when pieces are lost, stolen, or below the threshold?
7. What does the design admit it hasn't solved?

Terms, defined before use:
- Agent: a software helper that acts on your behalf — moving money,
  touching customer data, changing real systems.
- Secret: a key, credential, or token that unlocks something valuable.
- Holder: a gated agent whose only job is holding one piece of a split
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

Naming note: an earlier draft called holders custodians. Custodian
already means a custody bank, and the reader of this document is a bank
risk team — so the word is retired here.

The problem

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

The adversaries

A threat model that never names the adversary can't be judged. "Separate
teams" and "receipted" mean different things against different attackers.
The checks below are judged against these five. The same answer is
strong against one and weak against another, and that difference is the
point.
- A compromised holder: holds at most one piece, and one piece reveals
  nothing. Kill it, re-split, and the stolen piece is mathematically
  dead. This is the case the design handles best.
- A malicious insider: someone with legitimate access. If they hold one
  admin role, they hold at most one piece — same as a compromised
  holder. But an insider who can authorize a rebuild is in the room by
  design, and a receipt of their action is detection after the fact, not
  prevention. Insiders with legitimate access are the main remaining
  path, and no split removes that.
- An attacker on the reconstruction host: root on that host reads sealed
  memory before any receipt exists. Receipts detect and attribute the
  rebuild; they do not prevent observation. See the window section.
- The vendor itself: by default the vendor holds zero pieces and can
  never reconstruct alone. In the availability option, the vendor holds
  pieces that alone reveal nothing and can never rebuild without the
  customer's pieces. What the vendor does operate is the verification
  and receipt infrastructure — which is why receipts are third-party
  verifiable with a public key, not a vendor's word.
- A nation state: this design does not claim to stop one. An adversary
  that can compromise the customer environment itself, or K holders
  across separate domains, defeats the split. What the design buys
  against such an adversary is a higher bar — K coordinated breaches
  across separate teams, not one — and a record of every release. Not
  immunity.

The shape

Don't give any agent the secret. Split it across several holder agents,
so no single one holds enough to matter. Each holder's grant is tiny and
exact: it may release its piece only to a verified request from an
authorized identity, for an authorized purpose. Every release is
receipted. Any holder can be killed instantly. If one is killed, the
remaining holders split the secret again into fresh pieces — and old
pieces are mathematically dead against the new split, not revoked by an
admin claim. Nobody has to trust a revocation; the maths does it.

The machinery underneath is three primitives: a permission slip, a
proof, and an off switch. Everything else in this document is those
three, applied to the problem of holding secrets.

The window

This is the section most designs skip, and it is the one that decides
whether the rest can be trusted. A design that can't answer this section
is not a design to deploy — no matter whose name is on it.

Rebuilding a secret — for a job, or to re-split it after a kill — means
the secret exists whole again somewhere, for a moment. Here is that
moment, stated plainly:
- Where: in ephemeral sealed memory, never written to disk. The
  deployment names the exact machine and its operator — an unnamed
  window is no answer.
- Who is in the room: a human authorizes it, plus the holder agents
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

The trust boundary

This design does not claim no trust. It names exactly who you trust, for
what, and what they alone can and cannot do.
- Separation means separate teams, separate credentials, separate
  approval chains — not five accounts held by one team. One team holding
  all five holders is one trust domain wearing five hats, and that is
  not separation. That is a deployment requirement, not a suggestion.
- Default: the customer holds everything. The vendor holds zero pieces.
- Option for availability only: the vendor holds pieces that alone
  reveal nothing and can never rebuild without the customer's pieces.
  The customer holds enough to reconstruct alone, so the vendor alone
  can never reconstruct.
- Any single insider, admin, or compromised holder holds at most one
  piece. One piece reveals nothing.

The limit, stated plainly: wherever the customer holds enough to
reconstruct — default or availability option — the customer environment
is itself a single point of compromise. A breach inside the bank defeats
the split. The split protects against the vendor's risk and against a
holder being breached, not against a breach inside the bank. Naming that
limit is what makes the rest believable.

What fails closed

Reference configuration, illustrative only — 3-of-5: three holders must
release to rebuild. Thresholds per secret class are still open (see
What's open); 3-of-5 is the example used here to make this section
checkable, not a deployment claim.
- Two holders down: still serving. Three must release, so losing two
  still rebuilds.
- One compromised: nothing, on its own. Kill it, re-split, and the
  stolen piece is mathematically dead.
- Below the threshold (fewer than three available in the example): the
  system refuses rather than risking a bad rebuild. Fail-closed is the
  feature, not the bug.
- Through any single-holder loss, service continues with zero
  interruption. Recovery time below the threshold is the time to restore
  a holder and re-split, stated per deployment — it depends on the
  customer's provisioning speed, so no universal number is claimed here.

What's open

These are not decided, and they are not hidden:
- Default thresholds per secret class.
- Whether a denial spike triggers a human kill or an opt-in automatic
  kill.
- Whether reconstruction inside the HSM is feasible against real
  hardware.
- How separation is evidenced per customer.

This document exists to be checked — against this design, and against
any other. Run the checklist at the top against a different vendor. If a
vendor can't answer the window, that's the answer. If this design's
answers don't survive, it changes here, in public, before anyone deploys
it.

From the UCII project. Concept only — not part of any shipped product.
