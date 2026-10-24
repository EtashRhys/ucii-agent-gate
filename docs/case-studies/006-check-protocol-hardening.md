# Case Study 006: The Check Protocol, Hardened

**Three self-disclosed weaknesses in UCII's authorization check protocol — fixed, deployed, and proven with live adversarial tests, in one session (2026-10-23).**

UCII's delegated-authorization check is the moment the system exists for: an agent's gate sends a signed request to the server — *this identity, this operation, this exact command, now* — and the server answers whether a human-granted authority covers it. The gate executes only on a yes.

On 2026-10-20, in a written research proposal, we disclosed three weaknesses in that protocol, in two sentences:

1. The server did not enforce timestamp freshness or keep a replay cache for check requests.
2. The signed check message carried a truncated command fingerprint — 16 hexadecimal characters (64 bits) of the SHA-256 digest, rather than the full digest.
3. The authorization response was not itself signed.

Nobody had found these from the outside. We wrote them down ourselves, as known limitations, and on 2026-10-23 we closed all three — in that order of ascending blast radius — each under a rollback tag, each proven against production before the next began, and each logged against the exact proposal sentence it superseded.

## Fix 1 of 3 — Freshness window and replay cache (proposal weakness 1)

The signed check message always carried a timestamp. The server simply never read it: a captured signed check request could be re-presented indefinitely.

The check endpoint now enforces, after the credential proof verifies and is bound to the requested identity (never before — unauthenticated fields are not acted on):

- **Freshness:** requests whose timestamp is more than ±300 seconds from server time are rejected (HTTP 400).
- **Malformed timestamps** are rejected the same way.
- **Replay:** the hash of each accepted request's signature is cached for the window's duration; a byte-identical re-presentation inside the window is rejected as a replay. Clients following the documented flow sign a fresh message per check, so no legitimate byte-identical replay exists.

**Live battery (signed with the production agent's real credential): 7/7.** Fresh request authorized; identical replay rejected; timestamps at −600 s and +600 s rejected; properly signed malformed timestamp rejected; a fresh destructive request still evaluated to denied (freshness passes it through — authority decides); a fresh distinct request after a replay rejection authorized.

## Fix 2 of 3 — The full command fingerprint (proposal weakness 2)

The check message is now `ucii-gate-check-v2` and carries the **full SHA-256 hex digest** of the command. A 64-bit binding was below the standard of everything else in the system: a collision against a hall pass's stored hash was a feasible search, not a theoretical one.

Cutover mechanics, chosen because the operator controls both ends and there are no other clients yet:

- The server's hall-pass matching accepts v2 (full digest) and legacy v1 messages.
- A v2 message also matches a legacy stored hash via its first 16 characters — so a hall pass granted before the cutover keeps working until it expires.
- A v1 message **cannot** spend a full-hash pass. The weak format does not get to use the strong binding.
- New hall passes store the full digest.

Found during pre-flight, recorded plainly: the database column for the pass hash was declared `String(16)`, sized for the truncated hash. It is now `String(64)`. (SQLite never enforced the length; the declaration now matches what is stored.)

**Live battery: 7/7.** Full-hash pass + exact command authorized; different command denied; legacy pass honored under both v2 and v1 messages; v1 against a full-hash pass denied; fresh v2 read authorized; v2 with a stale timestamp rejected — the freshness fix composing with the new format untouched, because both message versions share the same field layout.

## Fix 3 of 3 — Signed check responses (proposal weakness 3)

The request was authenticated; the answer was plain JSON. Anything able to tamper with a response in transit — a compromised proxy, a TLS-terminating middlebox, a future deployment path we don't control — could flip a verdict.

Design, after an independent design review of the operator's own proposal (the review caught a downgrade hole in the original transition plan — verify-if-present lets an attacker strip the signature and be accepted; the shipped design has no such phase):

- A **dedicated ML-DSA-65 keypair** whose only job is signing check responses (key id `check-signing-2026-01`). Custody: a 0700 directory, secret file 0600, owned by the service user. The secret has never appeared in a log, a repo, or a message.
- **Every** response is signed — allows and denials alike — over a domain-separated canonical payload (`ucii-check-response-v1`) covering every security-relevant field: the verdict, the authority, the credential status, the key id, a SHA-256 of the exact request message, the server timestamp, and an explicit 30-second expiry.
- The service loads the key at startup and **refuses to start without it** (proven: with the key removed, the process exits at import and never serves).
- The gate **pins** the public key and requires a valid, unexpired, request-bound signature before it reads the verdict. Hard cutover. A verification failure is a hard denial — it never routes to the local-policy fallback that exists for an *unreachable* server. An untrustworthy answer and no answer are different events, and the gate treats them so.

**Adversarial battery against the gate's verifier: 15/15.** Flipped verdict, modified authority, changed credential status, changed timestamps, extended expiry — rejected. Signature removed — rejected. Wrong key, substituted key id — rejected. A genuine response replayed against a different request — rejected. A properly signed but expired response — rejected. Valid signed allow — accepted. Valid signed denial — accepted as authentic, and the gate denies on it.

One incident from the deployment, recorded because it is the point: the verifier's first version contained a bug (a missing import in the new code path). The first gated command after the swap was **denied** — the operator's own agent, locked out by its own gate, because a verification-path exception is a denial, not a shrug. The repair was made over the break-glass access path, verified, and only then did work resume. The rails bind the operator first. That is what they are for.

## Cross-cutting note

The same week this protocol was hardened, the gate's command classifier had been rebuilt under an adversarial battery of its own (case study 004). During this session it repeatedly denied the operator's agent legitimate work commands whose shapes it could not classify — including `git -C <path> <subcommand>`, which the classifier does not parse and therefore fails closed on. Annoying, worked around with plainer command shapes, and correct: a security boundary that makes exceptions for its own operator is a story, not a boundary.

## What this does not establish

- **Response authenticity is not decision integrity under server compromise.** A compromised API could still mint verdicts; neither this fix nor a simple external signer prevents that (a signer that signs whatever it is handed changes custody, not truth). That is a separate, larger architectural problem, and it is not claimed here.
- **Legacy v1 check messages remain accepted for hall-pass matching**, as a documented compatibility bridge for pre-cutover passes. Retiring v1 entirely is a separate future decision.
- An explicit random request nonce (rather than timestamp-plus-signature uniqueness) was identified as good future hardening for a v3 message format. It is recorded, and deliberately out of scope here.
- UCII still has **zero independent users**. These results describe one operator's production system, exercised by its own agent, with the receipts published. Independent evaluation remains the open gap — and the reason the weaknesses were disclosed in writing in the first place.

## Method note

Every fix followed the same discipline: the affected proposal sentences were audited first; a rollback tag pinned the pre-change state; the change shipped with a live adversarial battery, not code inspection alone; and a log entry named the exact disclosed sentence each fix superseded. The proposal now reads as what it is — a snapshot of the system on 2026-10-20 — with a living log of what changed, when, and on what evidence.

*Commits: private UCII repository `8ff1c11` (freshness/replay), `f4a860f` (fingerprint v2), `fb70761` (signed responses); gate publication in this repository. Evidence files retained by the operator.*
