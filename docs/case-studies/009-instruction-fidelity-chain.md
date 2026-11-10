# Case Study 009 — Instruction-Fidelity Receipt Chain: Catching Drift Between Agents

**Date:** 2026-11-10
**Status:** Built, tested, and live in production (DB + API + Gmail proxy + SSH gate)
**Rollback tag:** `rollback-pre-fidelity-chain-20261110`

## The problem

An instruction can change as it passes from one agent to a sub-agent, and a
before/after receipt cannot see it. The receipt looks clean while the
instruction drifted mid-pass. A human says "cancel the subscription"; by the
time the third agent acts, it has become "handle the billing cleanup" — and
nothing in the receipt shows the change.

The statement check (live demo, case 4) already caught one form of this: a
valid signature on a drifted restatement returns a signed drift verdict
(statement verified, not authorized). But it bound only the origin and the
restatement. What was missing was the full per-hop chain: a signed record at
every handoff, so the drift can be located at the exact agent that changed
the words.

## The decisions (operator, Nov 10, 2026)

Four decisions, all made before the build:

1. **Origin fingerprint: the first agent that receives the words.** The
   human's device does not compute fingerprints; the first agent receives the
   words and starts the work. That is where trust starts.
2. **Produce always, require only where the grant says so.** Receipt data is
   captured every time; an unbroken chain is required only where the grant
   says so.
3. **Chain storage: alongside existing receipts in the production database.**
   One auditable unit; a separate log risks drift and a split audit trail.
4. **Mismatch response: flag-only.** A mismatch can be benign — a legitimate
   rewording never recorded as its own handoff. Suspending on a mismatch
   would break the agent's work on a false alarm. The break is recorded and
   surfaced; the human decides. Killing stays human-operated.

## The chain module (8 tests, all pass)

A core module implements the chain: origin fingerprint (SHA-256 of the exact
text, no cleaning before hashing), signed hop records (ML-DSA-65 over a
canonical JSON of the hop fields), chain walking that locates drift at the
exact handoff, and a signed statement before acting. Eight tests prove it:

1. Clean chain verifies.
2. Drift at the second agent is located exactly.
3. Drift at the first hop is located.
4. A tampered hop returns `bad_signature`.
5. Broken continuity returns `gap`.
6. An empty chain returns `gap`.
7. A statement signs and verifies; a drifted restatement gives a different
   fingerprint.
8. The fingerprint is exact-text (a one-word change changes the hash).

## The production API (live)

Two endpoints, on the production server:

- `POST /v1/verification/fidelity/hops` — records one signed hop. The
  signature is verified against the helper's ACTIVE ML-DSA-65 credential
  before the hop is stored. A bad signature is rejected (400).
- `GET /v1/verification/fidelity/chains/{chain_id}` — returns the chain (all
  hops, in timestamp order) plus a verification verdict: `clean`, `drift`
  (with the exact handoff and helper), `gap`, or `bad_signature`. Flag-only:
  it reports the break, it never denies or suspends anything.

Proven live with a test identity:

- **Clean chain (2 hops), no drift → verdict `clean`.** Both hops stored
  (201), chain verified clean, 2 hops checked, no drift, no gap, no bad
  signature.
- **Drift chain (2 hops), second hop changed the words → verdict `drift`.**
  The verdict located the drift at the exact handoff (hop 2) and named the
  helper identity. The origin was "cancel the subscription"; the second hop
  passed "handle the billing cleanup".

## The substrates record hops

The chain is only useful if the agents that pass work actually write hop
records. Two substrates do, live:

- **Gmail proxy.** After every successful op, the proxy signs a hop record —
  what it received (instruction + qualifiers, fingerprinted) and what it
  acted on — and posts it to the fidelity API. Best-effort: a failed hop
  POST never undoes the op (the op already happened). A `--chain-id` flag
  groups ops for one piece of work. Proven live: a list op stored a hop, and
  the chain verified `clean`, received == passed.
- **SSH gate.** After every allowed command, the gate signs a hop record —
  the command, fingerprinted, received == passed (the gate runs the command
  as-is) — and posts it to the fidelity API. Best-effort: a failed hop POST
  never blocks the command. Proven live: a test hop stored and verified
  `clean`; the live gate now writes a hop for every allowed SSH command, and
  the production database holds those hops.

## What it proves

- The handoff problem has a working answer: a signed, verifiable chain that
  locates drift at the exact handoff, not just a before/after receipt that
  can look clean while the words changed.
- The chain works across substrates (SSH gate and Gmail proxy) with the same
  module, the same API, and the same verdicts.
- The response is flag-only by design: the chain reports the break, the
  human decides. The kill switch stays human-operated.

## Honest limits

- The chain is a receipt and audit trail, not an enforcement mechanism. The
  gate records hops but does not refuse a command when the chain shows drift.
  That is the flag-only decision, not an oversight — but it means the chain
  catches drift after the fact, it does not prevent the drifted action.
- A three-agent chain (parent → subagent → proxy, with the instruction
  passing through all three and the chain verified) has not yet been proven
  end-to-end. The two-hop chains are proven; the full three-hop shape is the
  next test.
- The chain records what each helper received and passed on. It does not
  judge whether the origin instruction was wise. Fidelity to origin, not
  wisdom of origin.
