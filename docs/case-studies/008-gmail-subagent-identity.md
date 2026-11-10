# Case Study 008 — UCII Gating Gmail: First Non-SSH Substrate and First Subagent Identity

**Date:** 2026-11-10
**Status:** Proven end-to-end (test scope, test account only)
**Test account:** a dedicated test Gmail account (test emails only)
**Test identity:** `gmail-test`
**Receipts:** 25 JSON files (held with the private evidence; the ledger below
summarises every receipt by decision)

## Summary

A subagent acted with its own UCII identity (`gmail-test`) and did Gmail work
— list, read, send, attach, reply, archive, mark-read, draft, label — through
a proxy that checks with UCII before every action and writes a signed receipt
after every action. The grant model took Gmail operations with zero server
changes: the operation is just a string, matched exactly against the grant.
The kill switch worked on the subagent identity (revoke → work stops dead
instantly; restore → work resumes). The subagent could not do what was not in
its grant.

This is the first UCII identity for a non-SSH substrate, and the first time a
subagent acted under its own UCII identity.

## What it proves

- UCII is not SSH-only. The grant takes any operation string (exact match, no
  fixed op set). Gmail ops worked with zero server changes. If there is a
  choke point that checks first, UCII can gate it.
- One agent can run many subagents, each with its own identity, own grant,
  own kill switch. A client needs one agent account, not one per job.
- The receipt carries the instruction and its qualifiers BEFORE and AFTER, so
  a mid-pass instruction change would show up. A clean before/after can no
  longer hide a drift.
- The kill switch works on a subagent identity. Revoke it and the work stops
  dead, instantly. Restore it and it works again.

## The identity (production database, read live)

Identity:

- id: `8770d176-02ea-4bae-9d5b-b88aabc73378`
- name: `gmail-test`
- type: `AI_AGENT`
- active: yes
- created: 2026-11-10 17:10:14 UTC

Credential:

- id: `4cd214f4-0109-41d7-b20e-5865a0d30d35`
- type: `ML_DSA_SIGNING_KEY`
- algorithm: `ML-DSA-65`
- fingerprint: `161709c0f5afabed95065c2cc2cd34209ff82c674b582685488d14e1125ab398`
- key_version: `1`
- status: `ACTIVE`
- Private key generated on the operator's machine (customer-side keygen). It
  never left that machine.

Authorities (grants) — both on record, history kept:

- (a) id: `48d5aecf-a24e-4254-8df0-a14018a8124e`
  - status: `REVOKED` (the kill test)
  - granted: 2026-11-10 17:10:14 UTC, by UCII Admin
  - revoked: 2026-11-10 17:16:24 UTC
  - reason: kill-switch test (operator-approved)
- (b) id: `0d37c183-bba6-4e4e-94b8-f4b402501849`
  - status: `ACTIVE` (the restore — a NEW authority; the revoked one stays on
    record, never reactivated)
  - granted: 2026-11-10 17:16:54 UTC, by UCII Admin

Both carry the same 9 ops:

```
gmail.list, gmail.read, gmail.send, gmail.attach, gmail.reply,
gmail.archive, gmail.mark_read, gmail.draft, gmail.label
```

NOT in the grant: `gmail.forward`, `gmail.trash`.

## The proxy

A Python script (not a service). For every op it: loads the identity config →
runs local policy gates (known op, in grant, send allowlist + `[UCII TEST]`
subject) → ML-DSA-65-signed UCII check
(`POST /v1/authorization/delegated/check`) → executes via the Gmail connector
→ writes a signed receipt JSON. Fail-closed at every step: no config, bad
config, unknown op, not in grant, allowlist violation, signing failure,
check-call failure, or server denial all refuse with exit 2 and a denial
receipt.

## The receipt ledger (25 receipts, by decision)

Fail-closed (no identity yet — proxy refused, exit 2): 4 receipts, all
`gmail.list` / `gmail.send`, decision deny (no config / bad config).

Wrong database (first provisioning went to the dev DB, not production): 2
receipts, both `gmail.list`, decision deny (check timed out / 403 identity not
authorized). Root cause found and fixed: the API reads the production DB, not
the dev DB. The stray dev-DB copy was deleted. Provisioning scripts must set
the production database URL before importing the server package.

Allow path (production identity, UCII authorized=true, ACTIVE): 11 receipts
covering all 9 granted ops — `gmail.list` (3), `gmail.send` (2),
`gmail.read`, `gmail.attach`, `gmail.reply`, `gmail.archive`,
`gmail.mark_read`, `gmail.draft`, `gmail.label` — all allow. The attach test
carried a CV attachment (verified by hash on arrival); the reply test answered
a setup email in-thread; the draft test created a draft in the test account.

Deny path (server + proxy): 2 receipts, both `gmail.forward`, decision deny
(not in grant — refused by the local gate before any UCII call, and by the
server on a direct signed check).

Scope error (UCII allowed it; Gmail's token lacked the scope): 1 receipt,
`gmail.archive`, decision error, authorized=True, ACTIVE. The test account's
token had readonly + send, not modify. The modify scope was granted, then
archive / label / mark-read passed (see allow list above).

Kill test (authority revoked → proxy stopped dead): 1 receipt, `gmail.list`,
decision deny, authorized=False, authority=REVOKED. Decision "UCII denied:
REVOKED", exit 2, no Gmail call made. Restore (new ACTIVE authority) →
proxy allowed again.

Subagent test (a subagent acting as `gmail-test`, proxy only): 4 receipts —
`gmail.list` allow, `gmail.read` allow, `gmail.send` allow,
`gmail.forward` deny (not in grant). The subagent's send arrived in the
operator's inbox; its forward was refused before any Gmail call.

## One receipt, in full (the subagent's send)

Receipt id: `68fac578-98dc-4914-a94f-944e37928748`
Op: `gmail.send` | Decision: `allow`
Identity: `8770d176-02ea-4bae-9d5b-b88aabc73378`

Instruction (the fidelity point — before AND after):

- before: "send a test application email to the operator"
- after: "send a test application email to the operator"
- qualifiers before: "test only, [UCII TEST] subject, only if the recipient
  is the operator"
- qualifiers after: "test only, [UCII TEST] subject, only if the recipient
  is the operator"

They match here. If the instruction had drifted mid-pass, the before and
after would differ and the receipt would show it.

UCII check (the server's own signed answer):

- authorized: True
- authority_state: ACTIVE
- authority_id: `0d37c183-bba6-4e4e-94b8-f4b402501849`
- server_key_id: `check-signing-2026-01`
- server_signature: present (ML-DSA-65, verifiable with the public key at
  `GET /v1/authorization/delegated/check-signing-key`)

Result: the send arrived in the operator's inbox with `[UCII TEST]` in the
subject; the body hash and action hash are recorded in the receipt.

## What was verified independently

Every receipt was re-read from disk and the decisions, the identity id, the
UCII authorized flags, and the instruction + qualifiers on both sides were
confirmed. Both test sends were confirmed in the operator's inbox. The
identity + both authorities + credential were confirmed in the production
database by direct read. The kill was verified by the proxy denying with
REVOKED, and the restore by the proxy allowing again with a new authority id.

## Honest limits

- `gmail.trash` was deliberately left out of the grant.
- The subagent was instructed to use only the proxy. It could technically
  call Gmail directly if it chose to. The side door is closed by the grant +
  instruction, not by removing its keys. For a real customer, enforcement is
  that the agent has no direct Gmail access at all — only the proxy does. That
  hardening is the next step, not this test.
- Web-form applications are still parked (email half only).
- The test identity is a test identity: it is tied to the test Gmail account,
  sends are allowlisted to the operator only, and it gates Gmail only. A real
  pilot identity gets a fresh keypair generated on the customer's own side, a
  grant from that customer's own requirements, and a proxy pointed at that
  customer's Gmail.
