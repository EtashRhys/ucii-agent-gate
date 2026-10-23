# Case Study 005 — Replace and Hall Pass: The Customer Flows, Exercised End-to-End

**Date:** 2026-10-23
**Component:** the UCII customer self-serve flows — grant replace, the self-serve grant rails, and the $25 hall-pass destructive window
**Status:** all flows exercised live on production; one recovery path proven by necessity; three usability defects found and recorded

## Why this exercise existed

Case study 002 closed with two honest admissions under "not established": the customer **replace-grant** flow and the **hall-pass** flow had been inspected in code but never exercised live. Code inspection tells you what a flow is supposed to do. Only running it tells you what it does — and what it feels like to be the customer while it does it.

On 2026-10-23, the day after 002 published, we ran both flows end-to-end on production, against a real authority, with the operator's own agent as the subject. Before the first test could start, reality added a third exercise we had not planned.

## The unplanned exercise: a lost control secret

A customer's grant is managed with a **control secret** — a human-held credential, issued once, that the agent never sees. Replace, kill, and hall-pass requests all require it. The test plan assumed the operator had his.

He did not. The secret for the subject authority had been displayed once, in an API response the previous day, and never recorded. It had not been emailed; it existed nowhere recoverable.

That accident produced the exercise's first finding, stated plainly:

**A customer who loses the control secret has no self-service recovery. None.** The only path back is an operator reset: the operator revokes the grant and issues a new one with a fresh secret. We ran that path live — revoke, then re-grant with a new secret delivered to the human, who recorded it this time. Elapsed time was in line with case study 002's operator revoke-to-restore timing (3m 04s). The system fails safe — a lost secret locks the human out rather than letting anyone in — but the recovery is a support event, not a button. Customers should be told that at onboarding, in so many words: *if you lose this secret, contact the operator; there is no reset link.*

## Test 1 — replace: narrow the grant, then restore it

Using the customer panel and the control secret, the grant was replaced with a narrower set (read, git, file-op — service removed). Verified from the gate's side: the three retained operations were allowed under the new authority; a service-class probe was denied. The grant was then replaced back to the full standard set, and all four operations verified allowed again.

One behaviour worth documenting for customers, confirmed in the server code and consistent with the live run: **a replace carries the control secret over to the new grant.** The same secret keeps working across replaces; no new secret is issued. (A kill is different — it destroys the secret with the grant, and restoration means a fresh operator grant and a fresh secret.)

## Test 2 — the rails: can replace be used to escalate?

Replace accepts the list of operations the customer wants. The question that matters: can a customer replace their way *upward* — specifically, to destructive?

We sent a crafted replace request naming the four standard operations plus the destructive operation. The server refused it — HTTP 403, "not grantable via customer self-serve" — and the check happens **before** the existing grant is touched, so a refused attempt changes nothing. Gate-side verification afterwards: the original grant, unchanged, all four operations allowed.

The precise characterization, now live-proven: replace does **not** enforce subset-of-current — Test 1's restore legitimately re-added an operation that had been removed. What it enforces is a global ceiling. The customer-grantable set is exactly the four standard operations; destructive is not in it, and no sequence of replaces can reach it. Replace is a lateral move inside a fenced set, never a ladder.

## Test 3 — the hall pass: one command, one window

The hall pass is the product's answer to a legitimate need inside a hard rule: destructive is never a standing grant, but a customer may occasionally need *one specific* destructive command run. The flow is three steps across two roles:

1. **The customer requests** a pass from the panel, naming the exact command, character-for-character, authenticated by the control secret. The request sits PENDING.
2. **The operator approves** — after verifying the $25 payment — from the operator panel. Approval generates a one-time activation key, shown once; only its hash is stored. The key reaches the customer out-of-band (email).
3. **The customer activates** with the request ID, the key, and the control secret. The two-hour window starts at activation, not approval. Activation burns the key.

We ran the full flow on production with a staged, harmless target — deleting a throwaway file created for the test. Timestamps (UTC): request 21:37:50, approval 21:48:48, activation 21:52:40, window expiring 23:52:40.

With the pass ACTIVE, we put signed authorization checks to the production server — the same check an agent's client makes before running a command (the check itself never executes anything):

- **The exact approved command: authorized.** The standing grant does not include destructive, so that yes came from the hall pass.
- **A different destructive command: denied.** The pass binds a hash of the exact command string; it authorizes that string and no other.
- **The exact command, checked again: authorized.** Checks do not consume the pass. The real semantics are *one exact command inside one two-hour window*; enforcement is per-check, so a client that checks before every execution gets exactly-one-command behaviour, and a pass can never drift to a different command.
- **The gate layer, separately:** with the pass active, the same command attempted through the operator's SSH gate was refused by the gate itself, before any server consultation — *destructive never goes through the gate*. That is a deliberate client-side doctrine adopted the same day (case study 004): the SSH gate declines to delegate destructive at all. Hall passes therefore serve agents that consult UCII directly through the API. The two layers are consistent; they are simply different clients with different postures.

The throwaway file was verified intact at the end. Nothing executed at any point in this test — authorization was the surface under test, and it behaved exactly as designed.

Two honest limits. The payment leg was attested, not exercised: the operator was approving his own test request, so no payment rail moved; what the approval step proves is that it is the gate through which every activation must pass. And the window's expiry was verified in code (the check requires an unexpired pass) rather than waited out for two hours.

## What the exercise found, beyond the passes

Running a flow as the customer is a usability audit whether you intend it or not. Three defects, all reproduced live, none of them in the authorization logic:

1. **Two look-alike strings, one card.** The customer panel's hall-pass card asks for a request ID and an activation key — both UUID-shaped, on the same card — and its own copy ("save your request ID, you'll need it to activate") invites entering the request ID *as* the key. We did exactly that; activation failed with "invalid hall-pass key" until the missing approval step was diagnosed from the server log. A customer receiving the key by email, days after requesting, is unlikely to hit this; anyone doing both roles in one sitting will.
2. **The one-time key can vanish in seconds.** The operator panel shows the key in the approval response, then re-fetches its pending list moments later, wiping the key from view. The key is unrecoverable by design — only its hash is stored — so an operator working on a phone can lose it before copying it, stranding the request in APPROVED permanently. (An approved-but-never-activated request has no expiry.) The fix is presentation, not cryptography: the key display must persist until dismissed, with a "copy this now — it is shown once" warning.
3. **One panel, two auth models.** The operator panel's authorities section would not load under the panel secret — it is guarded by a separate operator-lifecycle authorization — while the hall-pass section loaded fine with the same secret. Defensible design; surprising in the moment, and undocumented where the operator meets it.

## What this establishes

- The customer **replace** flow works in both directions on production, carries the control secret as designed, and cannot escalate past the four-operation ceiling — the refusal happens before the grant is touched.
- The **hall pass** works end-to-end: request, payment-gated approval, one-time key, activation, and authorization that covers exactly one command string for exactly one window.
- The **lost-secret** path is characterized honestly: no self-service recovery exists, the operator reset works and is fast, and the failure mode is lockout, not exposure.
- Case study 002's two "not established" items are now closed with production evidence — and the exercise repaid its cost in a different currency than expected: three customer-facing defects that no code review had surfaced, found by being the customer for an afternoon.
