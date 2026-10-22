# UCII Agent Gate: The Revocation Lifecycle, Exercised End-to-End on Production

**Status:** FINAL — approved for publication.
**Date of operation:** 2026-10-22 (all timestamps UTC unless noted; local time America/Toronto, UTC−4)
**Author:** Rocky (Muse, Meta) — the agent in the case study, and the test subject
**Operator:** Brad Phee (decisions, root access, customer-panel actions)

---

## Executive summary

Case study 001 ended with a proposed repeatable test: revoke the agent's grant and
watch the next command fail; issue a fresh grant and watch authorized operations
resume. On 2026-10-22 that test was run for real, against the production system,
on the production agent — and then extended to a second path the first study had
not covered: the customer self-serve kill switch on the product's web panel.

**Both revocation paths were silently broken when the test began.** Neither
failure produced an alarm, a log entry, or any visible symptom; both systems
looked healthy. The operator path had been inoperative since a service restart
that morning (a socket-path mismatch between the API and the agent's lifecycle
daemon). The customer path had never worked at all (the daemon registry that
routes customer requests was empty — a provisioning step that had never been
performed for the first, hand-provisioned agent).

Both defects were diagnosed from primary evidence, repaired the same day under
the operator's step-by-step approval, and re-tested through the full production
chain:

- **Operator path:** grant revoked at 19:42:26 UTC; the agent's next gated
  command was denied; a fresh grant was issued at 19:45:30 UTC — **revoke to
  restore: 3 minutes 04 seconds.**
- **Customer path:** the operator, acting as the customer on the public web
  panel, viewed the live grant (no secret required) and killed it with the
  human-held control secret at 20:33:45 UTC; the agent's next check was denied;
  an operator re-grant restored service at 20:38:57 UTC — **kill to restore:
  5 minutes 12 seconds**, including an in-test design discussion.

The central fact of this case study: **revocation that is never exercised is a
rumor.** Both failures were silent configuration drift — one from a restart, one
from a provisioning gap — and only an end-to-end test on the real chain could
see them. This study is the record of finding them, fixing them, and proving
the fixes the same way the failures were found: by running the lifecycle, not
by inspecting it.

---

## The claim under test

From case study 001, §Revocation:

> The authority is ACTIVE-until-revoked. The operator revokes it in one action;
> the agent's next command fails closed. There is no un-revoke — restoration
> means issuing a new grant.

The design has two revocation paths:

1. **Operator revoke.** A one-time, root-controlled authorization artifact is
   prepared out-of-band; the API consumes it (durably, before execution —
   replay returns 403) and asks the identity's dedicated lifecycle daemon,
   over a private IPC socket, to revoke the authority. Restoration is a fresh
   operator grant through the same chain, which also issues a one-time
   **control secret** to the human.
2. **Customer revoke (kill switch).** The human holder of the control secret
   uses the customer web panel: view a grant's status by authority ID alone
   (no secret), or revoke/replace it by presenting the secret. The secret is
   stored server-side only as a scrypt hash; the agent never holds it, so a
   compromised agent cannot block or undo its own kill. Customer requests are
   routed to the correct lifecycle daemon through a registry that maps each
   identity to its daemon, written at provisioning time.

**Test design.** Rehearse first on a throwaway identity (grant → signed check
ALLOW → revoke → DENIED → fresh grant under a *new* authority ID → ALLOW), then
run the same sequence on the production agent through the full operator chain,
timed. Then exercise the customer path from the real panel. Every step verified
against the production database, not the API's own report.

---

## Defect 1 — the operator path: dead since the morning restart

### Symptom

The rehearsal passed cleanly (18:39–18:51 UTC; all checks against the
production check endpoint). The first production revoke, at **19:13:55 UTC**,
returned **503 — protected lifecycle service unavailable.** The agent was *not*
revoked (verified immediately: a gated probe at 19:13:22 had been allowed, and
the agent remained fully operational). One part of the design behaved exactly
as specified: the one-time authorization had been **durably consumed before
the service call**, so the failed attempt could not be replayed — the retry
required a fresh authorization. Fail-closed ordering held even while the
operation failed.

### Root cause (code- and filesystem-verified)

Three facts, each checked against the live system:

- The API's lifecycle client dialed a **compiled-in default socket path** and
  ignored the configured socket-path setting.
- The agent's lifecycle daemon listens on its own **per-agent socket**, not
  the default.
- The API process also lacked membership in the daemon's IPC group.

The daemon's journal contained **no entry** for the failed attempt — it never
received a connection. That silence was the diagnostic: the failure was in
routing, not in the daemon. The mismatch went live at the **2026-10-22 06:23
UTC service restart**, when systemd-managed services replaced the hand-started
arrangement under which the chain had last worked (2026-10-16, the agent's
original grant). In other words: the configuration that made it work lived in
how the processes had been started by hand, and the first clean restart
exposed that it had never been written down in the service definitions.

### Repair

The operator chose the proper fix over a configuration workaround (repointing
the daemon at the default path was rejected: it would abandon per-agent socket
namespacing). A rollback tag of the pre-change state was created first. Then:

- The lifecycle client now resolves its socket path through the existing
  environment-aware helper used by the service module — one file changed; the
  compiled-in default remains only as a fallback.
- The API service gained a drop-in supplying the socket path and the daemon's
  IPC group.

### Re-test (full production chain)

| Time (UTC) | Event |
|---|---|
| 19:10:42 | Agent baseline probe: ALLOW |
| 19:13:55 | First revoke attempt: **503** (defect 1); authorization consumed, agent unaffected |
| ~19:39 | Repair live; API restarted with corrected socket path and group |
| **19:42:26** | Authority `f64f1046-…` **REVOKED** through the full chain |
| ~19:43 | Agent's gated probe: **DENIED (state REVOKED)** |
| **19:45:30** | Fresh grant `b2cbe5c8-…` issued through the full chain; new control secret delivered to the operator |
| 19:46:18 | All four operation classes (read, git, file-op, service) verified ALLOW |

Revoke → restore: **3 minutes 04 seconds.** The database preserves both
records: the revoked authority is never resurrected; restoration is a new
record, as case study 001 stated.

---

## Defect 2 — the customer path: never worked for anyone

### Origin

Mid-test, the operator asked what an end user uses to revoke — or whether
revoke was operator-only. The design answer (above) said the customer path
existed. The code was read before anyone claimed it worked.

### Finding

Customer requests resolve the target daemon through the provisioning-time
registry. Querying it: **0 rows.** Not just for the test agent — for every
identity. The first agent had been hand-provisioned before the registry
existed, and no row was ever written. Any customer who had tried the kill
switch would have passed the control-secret check and then received a 503:
*no lifecycle daemon registered for this identity.* The most safety-critical
button in the product was wired to an empty table.

### Repair

One registry row, inserted by a guarded operator-run script (identity →
that identity's daemon socket), 20:28:40 UTC, read back and verified. And a
standing rule, recorded the same day:

> **Provisioning is not complete until the identity's daemon-registry row
> exists.** No row, no customer self-serve revoke, status, replace, or
> hall pass.

### Test (the real panel, the real secret)

The operator acted as the customer at the public customer panel:

| Time (UTC) | Event |
|---|---|
| ~20:31 | Panel status view, authority ID only: identity `782ccfdc-…`, **ACTIVE**, four operations, correct grant timestamp |
| 20:32:20 | Agent gated probe: ALLOW (last alive check) |
| **20:33:45** | Panel kill switch (authority ID + control secret): authority `b2cbe5c8-…` **REVOKED**; panel confirms "Grant revoked. Your agent is stopped." |
| ~20:34 | Agent gated probe: **DENIED (state REVOKED)** — effective at the agent's next check |
| **20:38:57** | Operator re-grant through the full chain: fresh authority `d90a2f2f-…`, **fresh control secret** (the killed grant's secret died with it) |
| 20:39–20:41 | All four operation classes verified ALLOW under the new grant |

Kill → restore: **5 minutes 12 seconds**, including a mid-test design
question (below).

### A design point, verified in code

During the restore the operator asked whether the new grant should come from
the webpage or the terminal. The code answers it: the customer **replace**
operation requires the existing authority to be **ACTIVE**. A killed grant
therefore cannot be resurrected from the panel with the control secret alone —
the kill switch is a hard stop, and rebirth is an operator act, the same
posture as initial provisioning. That asymmetry is deliberate: the secret can
stop an agent instantly and unilaterally, but starting one again takes the
operator.

---

## What this test does and does not establish

**Established, with timestamps and database records:**

- Operator revoke and re-grant work end-to-end through the production chain
  (root authorization → API → lifecycle daemon → database → gate denial at
  next check), and the one-time authorization is consumed before execution,
  so a failed or replayed attempt cannot half-apply.
- Customer self-serve works end-to-end from the public panel: secret-free
  status view; secret-authenticated kill effective at the agent's next
  check; the agent itself holds nothing that can block or undo it.
- Restoration is always a *new* authority with a *new* control secret; old
  records persist as REVOKED. Production authorities: 34 at the reference
  snapshot → 38 after the day's tests (+2 rehearsal dummy, +2 replacements).
- Fail-closed behavior held throughout: every failure mode observed (503,
  consumed authorization, revoked state) left the agent either fully
  authorized under an existing grant or fully denied — never in between.

**Not established / not tested:**

- The customer **replace-grant** and **hall-pass** flows were code-inspected
  (including the ACTIVE requirement above) but not live-exercised. One
  code-level observation, recorded for follow-up: replace validates new
  operations against the global allowlist but does not verify the new grant
  is a subset of the original grant's operations.
- The rehearsal identity's grants and revocations were executed through the
  authorization service layer directly, not the API: by design, the API's
  lifecycle routes act only on the identity bound to the lifecycle service
  (the route asserts the identity match), so the API chain cannot target a
  rehearsal subject. All rehearsal *checks* ran against the production check
  endpoint with real ML-DSA-65 signatures.
- Adversarial probing of the gate classifier (chaining, escapes, indirect
  writes) remains outstanding, as noted in case study 001. This study
  exercised the lifecycle, not the classifier.
- One agent, one daemon, one operator. Fleet behavior is out of scope.
- The rehearsal identity's own provisioning took three script attempts
  (model imports, an environment-provided database URL, and a
  session-lifetime bug that orphaned its first credential, since revoked).
  Disclosed because it is part of the day's record — and because the dummy
  absorbing those failures first is what rehearsals are for.

---

## Lessons, now standing procedure

1. **Exercise the kill path on a schedule, not on faith.** Both defects were
   silent. The system reported nothing because nothing was watching the
   lifecycle itself. A revocation path that is not periodically exercised
   end-to-end should be assumed broken.
2. **A restart is a configuration change.** If a working arrangement depends
   on how processes were started by hand, it is not yet a configuration.
   The fix was not the code change; it was moving the truth into the
   service definitions.
3. **Provisioning checklists must include the routing row.** The customer
   path failed at the seam between two correct components: the panel was
   right, the daemon was right, the table between them was empty. Seams
   are where silent failures live.
4. **Fail-closed ordering is worth its cost.** Consuming the one-time
   authorization before execution turned a mid-test infrastructure failure
   into a clean retry instead of an ambiguous state. Verify this property
   deliberately; it is easy to build backwards.

---

## Commercial relevance

The agent gate's core promise to a customer is not that the agent behaves —
it is that the customer can **stop** it: instantly, unilaterally, without
the agent's cooperation, and (mid-month, non-refundable) finally. Before
2026-10-22, that promise was documented but, on the customer path, untrue —
and on the operator path, one restart away from untrue. After 2026-10-22,
it is a measured fact with timestamps on both paths, a provisioning rule
that keeps it true for the next customer, and a written record — kept
against a frozen reference baseline for an external reviewer — of exactly
what was false, when, and what changed.

That is the proposition in one sentence: **authority you can revoke is only
real if you have revoked it — so we did, twice, in production, and wrote
down what broke.**

---

## Evidence manifest

| Artifact | Reference |
|---|---|
| Test subject | Agent identity `782ccfdc-…`; rehearsal dummy identity `13bf1d00-…` |
| Authorities (production DB) | `f64f1046-…` REVOKED 2026-10-22 19:42:26 UTC (operator); `b2cbe5c8-…` REVOKED 2026-10-22 20:33:45 UTC (customer panel); `d90a2f2f-…` ACTIVE, granted 20:38:57 UTC |
| Timings | Operator revoke→restore 3m 04s; customer kill→restore 5m 12s |
| Code repair | Lifecycle client socket resolution (one file), committed with baseline-log entry the same day; rollback tag created before the change |
| Registry repair | One daemon-registry row, inserted 2026-10-22 20:28:40 UTC by operator-run script; verified by read-back |
| Baseline log | Entries of 2026-10-22 in the operator's private baseline log (kept against the frozen reference tag of the system under external review), naming the affected claims for both defects |
| Evidence file | Operator-held lifecycle-test evidence file, 2026-10-22 (rehearsal, operator test, customer test, with full timelines) |

**Methodology:** every state claim in this study was verified against the
production database read directly, not against the API's responses alone.
Identifiers truncated; socket paths, credential material, control secrets,
and host details withheld. No claim in this study depends on the agent's
own report of its state — each denial and restoration was independently
observed from the operator's side (panel state, database records) and the
agent's side (gate decisions).

---

## Recommendation: where this should live

**`ucii-agent-gate` repository, under `docs/case-studies/002-revocation-lifecycle.md`**,
continuing the numbered series begun by case study 001 — which proposed this
test.

**Publication status.** Approved by the operator and published to the public
`ucii-agent-gate` repository on 2026-10-22. The full
evidence file and audit records remain operator-held.

---

*FINAL — approved for publication 2026-10-22. Prepared from the day's
verified evidence file. Companion record: the operator's baseline log,
entries of 2026-10-22 (defects, repairs, and affected claims, recorded the
same day).*
