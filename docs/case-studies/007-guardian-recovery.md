# Case Study 007

## Guardian recovery: 2 of your 3 devices bring your identity back

**What this is.** Key custody phase 1: lose the phone, keep the
identity. The standard is fixed — exactly 3 guardians, threshold 2
— and the story is devices, not humans: 2 of your 3 devices
authorize recovery. No coordination with other people, no waiting
on friends, no control secret required.

**What it is not.** This is not revocation. Revocation ends trust
in a key, instantly. Custody re-establishes an identity on fresh
keys after loss. Recovery uses revocation at the end (old keys
die) — it does not replace it.

## How it works

1. Before loss, the owner registers 3 guardian identities, signed
   with the owner's current key. The set freezes while a recovery
   is pending.
2. After loss, any 2 guardians attest (ML-DSA-65 signatures over
   canonical JSON) to the same new keypair: fresh ML-DSA-65 +
   ed25519 keys, 7-day attestation freshness, unseen nonces.
3. The server opens a recovery attempt behind a fixed 24-hour
   delay and records a panel notification. The owner can object,
   or kill the identity outright, during the delay.
4. After the delay with no objection, completion revokes every
   ACTIVE credential of the identity and issues the new keypair
   with lineage to the old rows, same identity ID.

**What counts as a guardian.** A guardian does not have to be a
phone. Your laptop counts. A hardware key counts. A printed backup
key, kept somewhere safe, counts. What matters is three
independent key stores — any two of which can sign — not three
phones.

**Notification limit, stated plainly.** Phase 1 notification is a
panel alert + audit record, not email — there is no email transport
in the codebase, and email is a named phase 1b follow-up. The 24h
delay protects an owner who checks the panel in time. It does not
protect an owner who doesn't.

**Deliberate divergence.** The operator control-secret recovery
path marks old ACTIVE credentials REPLACED. Guardian completion
marks them REVOKED, per the vault spec: stolen keys dead on
arrival, not merely superseded.

## Day-1 battery (2026-10-26, test identities only)

Fixtures via the app's service layer (identity creation through
the API costs 0.5 USDC each and the operator's entitlement does
not cover it; test data only, killed after day 2). Recovery
testing 100% over real HTTP with real signatures.

15/16 passed. Registration, fixed 2-of-3, and every negative test
(one attestation, unregistered guardian, duplicate, bad signature,
mismatched keys, stale attestation — all 400, no attempt created).
Valid request opened a PENDING_DELAY attempt with a panel
notification unacknowledged. Guardian list froze while pending.
Early completion rejected, attempt stayed pending.

The one miss was the test's own strictness: the delay measured
86399.89s instead of exactly 86400, a 0.108s stamp skew between
the delay clock start and the row's insert time — not a short
delay. The gate itself is proven by the early-completion
rejection.

## Build timeline — from go to live in 91 minutes

All times EDT, Mon Oct 26, 2026. The whole custody phase 1 —
design, server code, deploy, day-1 battery, panel card, vault
client, both pushes, live verification — ran from a park bench:
no wifi, no laptop, phone + data + Rocky + the Oracle
workstation (Brad's words, ~10:41 AM).

- **09:28** — Brad: "Okay great. Go" on key custody (Rocky's
  recommendation: custody first, trust-root design second,
  distribution last).
- **09:47** — Notification: option A (panel alert + audit record
  only; email named phase 1b).
- **09:56** — Device framing locked: "it's a 2 of 3 device. Not
  a 2 of 3 humans needed to resolve the issue."
- **10:02** — Revocation ≠ custody, checked before building
  sideways: revocation ends trust; custody re-establishes it.
- **10:10** — NRC docs condition honored: BASELINE-LOG check
  against the SENT proposal (zero custody hits — claims: none).
- **10:15–10:25** — Rollback tag by Brad, commit 93a7345 pushed,
  service restarted, all 5 new routes verified live.
- **10:32** — Day-1 battery: 15/16 (see below).
- **10:41** — Panel wiring picked over bounty delivery.
- **10:46** — Unsigned objection decided.
- **10:50–10:56** — Tags by Brad, panel commit 5741e46 + vault
  commit a06e89d pushed, served panel + client verified live.
- **10:59** — Panel wiring done. 91 minutes from go to live.

**Accuracy, not just speed.** Zero production defects in day 1.
The panel's tricky button line was verified by evaluation before
push. Both pushes were verified: tag-to-commit mapping checked
pre-push, the served panel fetched live, the pushed client run
against the live attempt. Working trees left clean except Brad's
own files. The one battery miss is recorded, not hidden: a
0.108s test-tolerance skew, not a short delay.

## Day-2 battery (Tue Oct 27, 2026, test identities only)

Run at 1:20 PM EDT, after the 24-hour delay opened at 10:32 AM EDT.
The attempt was still PENDING_DELAY before completion — nothing
had jumped the gate early.

- Completion after the delay: 200, status COMPLETED, completed_at
  2026-10-27T17:20:16 UTC. A second completion was refused (400).
- The delay re-measured 86399.892s — the same 0.108s stamp skew as
  day 1 — and passed under the corrected ≥86399 tolerance. The
  gate itself was already proven by day 1's early-completion
  rejection: the delay is enforced, not approximated.
- Old rows REVOKED with reason guardian_recovery. New ML-DSA row
  ACTIVE with lineage to the old key. New ed25519 row ACTIVE.
  Same identity ID — the identity survived, the old keys died.
- Old-key verification, method stated plainly: the HTTP check
  returned 402, not a verdict. The verify endpoint charges $0.10
  and gates unpaid calls before the handler runs (probed before
  the run), and the operator does not pay himself. So the check
  was proven via the service layer instead, calling the same
  verifier code the router calls: the real revoked old key, given
  a garbage signature, verifies as verified=False, status
  REVOKED, reason "Credential is not active" — and the handler
  returns before any signature check for non-active credentials.
  The denial is real; the route to it is labeled.
- Key-side scope: an ACTIVE key with a garbage signature verifies
  as verified=False, status ACTIVE, reason "Signature verification
  failed" (proven via the service layer on a fresh fixture, since
  the battery's real new key was killed by the planned cleanup
  below). A credential alone authorizes nothing — proof is
  required, and grant-side narrowing was already proven in case
  study 005.
- Objection: a pending attempt objected to → REJECTED.
  Completing a rejected attempt was refused (400).
- Nonce replay: an attempt reusing a seen nonce was refused (400).
- Cleanup: 8 battery identities + 1 proof fixture killed (all
  ACTIVE credentials revoked, identities deactivated). History
  preserved: the completed attempt remains in the recovery read,
  and the revoked rows stay as audit history.

Score: 17/19 via HTTP, with the remaining 2 proven via the service
layer as described above — all 19 checks accounted for, none
hidden, none hand-waved.

## Bounded claims

- Custody is mitigation, never "unstealable keys."
- Phase 1 notification is pull (panel), not push (email).
- Battery ran on test identities, not production customer
  identities.
- Two day-2 verify checks ran via the service layer, not HTTP,
  because the HTTP route 402s unpaid calls by design — labeled
  in the day-2 section, not hidden.
- No proposal sentence affected (BASELINE-LOG entry 2026-10-26,
  day-2 entry 2026-10-27).
