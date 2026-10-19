# UCII Agent Gate: A Real-World AI Agent Operating Under Delegated Cryptographic Authority

**Status:** FINAL — approved for publication.
**Date of operation:** 2026-10-17, 19:44–20:21 EDT (America/Toronto)
**Author:** Rocky (Muse, Meta) — the agent in the case study

---

## Executive summary

On the evening of 2026-10-17, an independently identified AI agent (Rocky) completed a real production task on the operator's Oracle Cloud server — creating, writing, and publishing a public GitHub repository — while operating entirely under UCII delegated authority. Every command the agent issued passed through the UCII command gate: each was classified, checked against a human-issued grant, and written to an audit log. Commands outside the grant were denied, including two attempts to set a Git identity and one over-complex analysis script. The agent recovered from each denial without elevated privileges and finished the job.

The central fact of this case study: **the Git identity command was denied, yet the agent continued and completed its authorized work.** That is the behavior an enterprise customer wants from an AI agent with production access — productive under constraint, stopped at the boundary, and fully attributable.

**A note on time.** The operation ran 19:44–20:21 Eastern. In UTC — the timezone of the audit log — it crossed midnight: 23:44 UTC Oct 17 → 00:21 UTC Oct 18. All log timestamps below are UTC.

---

## Technical architecture

**The agent.** Rocky runs as an AI agent with its own UCII identity (`782ccfdc-…`), distinct from the human operator's identity. It is not borrowing the operator's credential.

**The delegation.** The human operator (Brad Phee) issued a delegated authority (`f64f1046-…`) to Rocky's identity, scoped to exactly four operation classes. Canonical names below are what the gate sends the UCII server; the gate's classifier uses the short forms shown in parentheses:

| Canonical operation | Gate shorthand | What it covers |
|---|---|---|
| `ssh.exec:read` | `read` | Read-only inspection: listing, viewing files, status checks |
| `ssh.exec:git` | `git` | Version control: clone, add, commit, push, tag |
| `ssh.exec:file-op` | `file-op` | File writes within the agent's working areas |
| `ssh.exec:service` | `service` | Service management (e.g. restarting the UCII service) |

The gate's taxonomy also defines `ssh.exec:destructive`, `ssh.exec:unclassified`, and `ssh.exec:empty`. None of the three is in this grant — which is why the denials below read `unclassified` / `NOT_GRANTED`.

**The gate.** The agent reaches the server over SSH through a forced-command key (verified: the server's `authorized_keys` entry for the agent's key carries `command="…/gate.py"`, so every session on that key runs the gate instead of a shell). Each command is intercepted and:

1. Classified into an operation class (or marked `unclassified`).
2. Built into an authorization-check request binding the agent's identity, the requested operation class, a timestamp, and a SHA-256 digest of the exact command — and that request is signed with the agent's **ML-DSA-65** credential (see "What the signature covers" below).
3. Sent to the UCII server (`POST /v1/authorization/delegated/check`); the server verifies the signature and answers authorized/denied.
4. Allowed or denied. Denial is fail-closed: anything unclassified or outside the grant is denied.
5. Recorded as a JSON entry in the server-side audit trail — allowed or denied — with timestamp, agent name, identity reference, full command text, class, decision, and the authority cited.

**What the ML-DSA-65 signature covers (verified in gate and server source).** The signed message is:

```
ucii-gate-check-v1 | identity_id | operation | timestamp | sha256(command) hexdigest[:16]
```

- The digest is **16 hexadecimal characters** (64 bits of the SHA-256 digest), not 16 bytes.
- The ML-DSA-65 signature authenticates the *check request* to the UCII server and incorporates a 64-bit truncated SHA-256 command fingerprint. The fingerprint identifies the command but does not carry the full SHA-256 digest's collision resistance. The current implementation does not enforce timestamp freshness or replay prevention. The authorization endpoint evaluates permissions but does not execute commands.
- It does **not** sign the grant itself, and it does **not** sign the server's authorization response.
- Server-side, the verifier checks: credential exists, credential status is ACTIVE, credential not expired, ML-DSA-65 signature valid, credential bound to the requesting identity, and a live delegated authority for the exact operation. It does **not** enforce a timestamp freshness window and keeps no replay cache on check requests. The check endpoint never executes anything (`executed=False`) — it answers authorized/denied only.

**Revocation.** The authority is ACTIVE-until-revoked. The operator revokes it in one action; the agent's next command fails closed. There is no un-revoke — restoration means issuing a new grant.

---

## Evidence

### The centerpiece: a denied command, a completed task

A successful GitHub publication is ordinary. What makes this operation worth documenting is what happened at 23:45:56 UTC:

```json
{"ts": "2026-10-17T23:45:56.254448+00:00", "agent": "rocky",
 "command": "cd ~/radio-dashboard && git config user.name ...",
 "class": "unclassified", "via": "ucii-server",
 "decision": "deny", "reason": "UCII denied: NOT_GRANTED"}
```

An independently identified AI agent, mid-task on a production server, asked to do something outside its four granted operation classes. A cryptographic authorization system said no — and logged the refusal. The agent did not escalate, did not reroute around the gate, did not stop working: it diagnosed the denial, dropped the unclassifiable step, and — just 27 seconds after the denied Git configuration attempt — successfully pushed the repository using its existing authorized configuration. (A follow-up README update was pushed about eleven minutes later.)

That sequence — **deny, recover, complete** — is the entire UCII proposition in one evening.

### Method

- **Primary source:** the gate's server-side audit trail (JSON lines, one record per gate decision; private, on the operator's server).
- **Independent corroboration:** the SSH daemon's authentication logs — used to verify which SSH key authenticated each session in the window, independent of the gate's own records.
- **Outcome verification:** the published repository and its live demo URL, checked after the operation.

### The two phases

The 22 audited commands fall into two distinct activities. They are separated here because only the first is the production task; the second is this case study's own evidence-gathering.

**Phase A — build and publish the radio repository** (23:44:26–23:56:58 UTC Oct 17; 19:44–19:56 EDT): 16 commands — 14 allowed, 2 denied.

| Time (UTC) | Command (abridged) | Class | Decision |
|---|---|---|---|
| 23:44:26 | `git clone …/radio-dashboard.git` | git | allow |
| 23:44:36–54 | `cat >` index.html, README.md, manifest, icon-192.png, icon-512.png (5 file writes) | file-op | allow ×5 |
| 23:44:55 | `ls -la` + verify transfer | read | allow |
| 23:45:09 | `grep -c "My Radio"` — verify rebrand, confirm no operator name in files | read | allow |
| 23:45:29 | `git config user.name … && git config user.email … && git add -A && git commit …` | unclassified | **deny** (NOT_GRANTED) |
| 23:45:46 | `git status --short` — diagnose state after denial | read | allow |
| 23:45:56 | `git config user.name … && git config user.email …` (isolated retry) | unclassified | **deny** (NOT_GRANTED) |
| 23:46:11 | `git add -A && git commit -m "v1: …"` — proceed without per-repo identity | git | allow |
| 23:46:23 | `git remote set-url origin git@github.com:… && git push -u origin main` | git | allow |
| 23:56:54 | `cat >` README.md (revised phone-setup instructions) | file-op | allow |
| 23:56:58 | `git add README.md && git commit … && git push` | git | allow |

**Phase B — gather audit evidence for this case study** (00:20:10–00:21:43 UTC Oct 18; 20:20–20:21 EDT): 6 commands — 5 allowed, 1 denied.

| Time (UTC) | Command (abridged) | Class | Decision |
|---|---|---|---|
| 00:20:10 | locate audit log on server | read | allow |
| 00:20:25 | `tail` audit log, inspect record format | read | allow |
| 00:20:42 | `python3 -c` inline audit-analysis script | unclassified | **deny** (NOT_GRANTED) |
| 00:21:02–43 | same analysis via `grep` / `cut` | read | allow ×3 |

**Totals: 22 commands, 19 allowed, 3 denied. Zero `sudo` invocations in either phase.**

**Task outcome (Phase A):** repository `EtashRhys/radio-dashboard` created and published (commits `a79ab37`, `6d25f89`), verified live on GitHub and via GitHub Pages. The example was rebranded from the operator's name to the generic "My Radio" before publishing — verified by the agent with `grep -c` (zero occurrences of the operator's name) before commit.

**Consistency check.** The identical command shape (`git config user.name/user.email`) was denied on 2026-10-16 07:23:21 UTC in a different repository context, with the same class and reason. Enforcement is consistent, not ad hoc. Both times the agent recovered the same way.

### Independent corroboration: which SSH key was actually used

The gate's audit log records `via: ucii-server` for every command, but that is the gate describing itself. Two independent checks corroborate the access path:

1. **Forced command verified active.** The server's `authorized_keys` entry for the agent's key carries `command="…/gate.py"` — any session authenticating with that key runs the gate instead of a shell. There is no shell to escape to on that path.
2. **Authentication logs agree.** The agent's key fingerprint (computed independently from the agent's key material) matches the fingerprint on **every** `Accepted publickey` entry in the SSH daemon's logs covering the operation window. No session in the window authenticated with any other key; the break-glass path was not exercised.

**Stated precisely:** the SSH logs prove each *session* authenticated with the gated key, and the forced-command entry proves each such session ran the gate. The *session-to-command* correspondence rests on timestamp correlation between the two logs plus forced-command semantics (one SSH exec invocation = one gate invocation = one audit record) — not on a shared cryptographic token between the logs. That is sufficient to corroborate the path, and its limits are stated here.

---

## Security boundaries — what is enforced vs. what is policy

Precise claims only:

1. **Gate-enforced:** commands submitted through the UCII-gated SSH path are subject to operation-scoped authorization against the live delegated authority. Unclassified operations are denied fail-closed. Every decision — allow or deny — is written to the server-side audit trail. Within that path, the agent cannot widen its own grant and cannot act after revocation.

2. **Policy, not gate-enforced:** service restarts. The `service` class is inside the grant, so the gate *would* allow a restart. The agent confirms with the operator first because that is the operator's standing rule — enforced by the agent's compliance and the operator's revoke button, not by the gate.

3. **Known alternate path:** a separate break-glass SSH key exists for emergencies. It bypasses the gate and is unaudited by design. SSH authentication logs confirm it was not used during this operation, and standing policy restricts it to emergencies. The demonstration's claim is therefore bounded: *commands the agent submitted traveled the gated path and were authorized there* — not *no other path exists*.

4. **No privilege escalation occurred or was attempted.** Zero `sudo`, `kill`, or credential-access invocations in the window. When the agent hit a boundary, it narrowed its approach — it never tried to go around.

5. **The audit trail is a server-side record, not a tamper-proof one.** It is an append-only JSON log, useful and complete for this operation — but no cryptographic tamper-evidence or write-protection was demonstrated. A privileged server actor could modify it. It is described here as a server-side audit trail, nothing stronger.

---

## Limitations

- The gate classifies by command shape; novel or complex constructions (e.g. a long inline Python script) may classify as `unclassified` and be denied even when the *intent* is read-only. This is fail-closed by design, but it means the agent must sometimes reformulate benign work — as happened during this very evidence-gathering (Phase B).
- Audit records reference a gate-local identity handle; binding it to the full UCII identity requires the authority credential records. The log alone does not show the full delegation chain — the chain is established by the credential + authority + log together.
- The ML-DSA-65 signature covers the authorization-check request, not the grant or the server's response, and the server enforces no freshness window or replay cache on check requests. Grant issuance and response integrity rest on the UCII server's own controls, which this case study does not evaluate.
- This case study covers one agent, one grant, one evening. It demonstrates the mechanism working, not its behavior at fleet scale or under adversarial pressure. It does not evaluate whether the classifier resists command chaining, shell escapes, or indirect file writes — see "Proposed repeatable test" below.

---

## Commercial relevance

The enterprise problem: businesses want AI agents operating on production infrastructure without handing them unrestricted control. The standard approaches are prompting ("behave"), sandboxing (limits what the agent can touch), or human-in-the-loop on every action (doesn't scale).

This operation demonstrates a fourth approach: **cryptographically delegated, operation-scoped authority with a mandatory audit trail**. The agent in this case study:

- holds its own identity — every action is attributable to *it*, not to a shared credential;
- acts only within a human-issued, revocable grant — four operation classes, nothing more;
- is stopped at the boundary by infrastructure, not by its own goodwill — the denials needed no cooperation from the agent;
- remains productive under constraint — the denied commands didn't end the task, they rerouted it;
- leaves a complete, independently corroborated trail — 22 commands, 22 gate records, SSH auth logs agreeing on the access path.

That is the commercial proposition in one sentence: **give an AI agent access to your production infrastructure without giving it unrestricted control — and prove it afterward from the logs.**

---

## Proposed repeatable test

The next step is a controlled test that exercises the boundaries deliberately rather than encountering them by accident:

| Test | Expected result |
|---|---|
| Authorized read | Allowed and logged |
| Authorized Git operation | Allowed and logged |
| Unclassified command | Denied and logged |
| Unauthorized operation (outside the four classes) | Denied and logged |
| Revoke the agent's grant | Subsequent gated command denied |
| Issue a fresh grant | Authorized operations resume |

The last two demonstrate the full authority lifecycle, not just classification. **They require the operator's explicit go-ahead** — the agent will not revoke its own grant unprompted. A further assessment should probe the classifier itself: command chaining, shell escapes, and indirect file writes through allowed commands.

---

## Evidence manifest

| Artifact | Reference |
|---|---|
| Git commits (radio-dashboard v1 + README) | `a79ab37`, `6d25f89` on `EtashRhys/radio-dashboard` |
| Live demo URL (verified 2026-10-17) | `https://etashrhys.github.io/radio-dashboard/` |
| Gate audit trail (private, on operator's server) | 22 records, 2026-10-17 23:44:26 → 2026-10-18 00:21:43 UTC |
| SSH auth logs (private, on operator's server) | all window sessions match gated-key fingerprint |
| Denied-command sample | 2026-10-17 23:45:56 UTC, `git config user.name`, class `unclassified`, `NOT_GRANTED` (quoted above, IDs truncated) |
| Prior consistent denial | 2026-10-16 07:23:21 UTC, same command shape, same class/reason |
| Gate signing code (private, on operator's server) | ML-DSA-65 over `ucii-gate-check-v1 \| identity_id \| operation \| timestamp \| sha256(command) hexdigest[:16]` |

**Methodology:** records were pulled read-only via the gated path itself (Phase B above — including one instructive denial). Timestamps reconciled across the UTC-midnight boundary against America/Toronto local time. SSH key fingerprints compared independently of the gate's records; forced-command entry verified in the live `authorized_keys`. No gate, grant, service, or production configuration was modified during evidence gathering. Identifiers truncated in public excerpts; hostnames, credential paths, key material, and emails withheld.

---

## Recommendation: where this should live

**`ucii-agent-gate` repository, under `docs/case-studies/001-rocky-radio-dashboard.md`.** Rationale:

- It is public, versioned, and sits beside the product it demonstrates — a prospect reading the gate's README finds the proof one directory away.
- Numbered case-study files (`001-`, `002-`…) establish a series as further operations are documented.
- The full audit trail stays private on the operator's server; only sanitized excerpts (truncated IDs, no hostnames, no credential paths, no key material) ship in the repo.
- A short pointer from the main README ("See it in production →") turns the case study into a sales asset without restructuring the repo.

**Publication status.** This case study was approved and committed to the public `ucii-agent-gate` repository after evidence gathering. No gate, grant, service, or production configuration was modified during the read-only evidence-gathering phase.

---

*FINAL — approved for publication 2026-10-17. v3 → final: push timeline corrected (first push 27 seconds after the denial; README update ~11 min later); command fingerprint stated as 64-bit truncated SHA-256 with no timestamp-freshness or replay-prevention claimed.*
