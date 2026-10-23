# Case Study 004 — Attacking Our Own Gate: The Classifier Battery

**Date:** 2026-10-23
**Component:** the UCII agent gate's command classifier (the agent-side component that prices each command into an operation class — read, git, file-op, service, destructive — before the UCII server authorizes it)
**Status:** vulnerabilities found, fixed, deployed to production, and re-tested clean the same day

## Why we attacked it ourselves

The gate's promise to customers is narrow and testable: *an agent can never exceed the authority its human granted.* The cryptography behind that promise is only half the system. Before any cryptographic check happens, the gate has to decide what a command **is** — and commands arrive as shell text, which is adversarial by nature. A read-only grant is only as strong as the classifier's ability to notice that `find . -delete` is not a read.

On 2026-10-22 we scored our own gate-hardening as "half done" for exactly one reason: revocation had been exercised end-to-end (case study 002), but the classifier had never been attacked. So we attacked it.

## Method

We built a battery of 127 test commands in 10 categories: payloads hidden inside read-only verbs, separator smuggling, command-substitution execution, redirect variants, wrapper confusion, destructive-command evasion, git boundary abuse, fallback-grant smuggling, exotic-but-legitimate control shapes, and a set of benign everyday commands that must keep working.

Each item was scored against four authorization profiles:

- **A** — a restricted customer holding a read-only grant
- **B** — a restricted customer holding read + git grants
- **C** — the operator's own agent under local-policy fallback (scored on *label honesty*: under an owner entitlement the operation may be legitimate, but the class recorded in the audit log must not lie about what the command does)
- **D** — local-policy fallback with a single explicit grant and no entitlement (the grant-scoping profile)

The harness is verdict-only: it calls the classifier as a pure function with stubbed server answers. No test command was ever executed. The target was pinned by SHA-256 to the exact file running in production.

## What the battery found

**Profile A (read-only grant): 36 of 122 scored items executed effects above the grant.**
**Profile B (read + git): 30.**
**Profile D: all 3 grant-smuggling attacks succeeded.**
**38 items were under-classified** — the audit log would have recorded a tamer class than the command's real effect.

The root cause was uniform: the read list trusted whole verbs and never inspected their arguments. Under a read-only grant, all of the following were priced "read":

- `find` with `-delete`, `-exec`, or `-fprint` — deletion, arbitrary execution, and file writing from a search verb
- `sed -i` (in-place edit), the `sed` `w` command (write to file), and the `sed` `e` command (execute)
- `awk` programs calling `system()` or the `getline` pipe — execution from a text processor
- `sort -o` and `uniq` with an output operand — quiet file writes
- `journalctl --vacuum-size` and `--rotate` — destruction of the audit trail itself, priced as reading it
- git boundary abuse: branch creation and deletion, `git remote set-url`, `git fetch` (which writes), and `--output` file writes on git reads
- `env` used as a launcher for other programs, and `date -s` (setting the system clock)

Separator handling had holes of its own: commands joined by a newline or a bare `&` were priced as a single command, so a harmless first command could carry a destructive second one at the first command's price. Command substitution (`$(…)`, backticks, process substitution) was priced by its harmless outer verb. And `2>` / `&>` redirects were stripped before the redirect check ran — a command could create files with its stderr and still be priced a read.

Under local-policy fallback, two further weaknesses: uppercase `rm -R` evaded the lowercase-only destructive patterns, unlisted destroyers (`truncate`, `shred`, `dd` to a file, `git clean`, `git reset --hard`) passed as merely "unclassified," and — most subtle — a fallback grant's pattern was matched against the *entire compound string*, so a grant naming one command silently authorized a second, different command riding in the same line.

The battery also **cleared five of our own suspicions**, and we record that with the same weight: `rm --recursive` was in fact caught (pattern overlap), split short flags were caught, flagged payloads inside compounds were caught, `awk`'s `print > file` was caught by the redirect check, and leading whitespace changed nothing. A test suite that only confirms fears is not measuring anything.

One tempering fact: the battery ran before any customer held a grant. Nothing walked through these holes. They were found in the lab, pre-launch — which is the only acceptable time to find them.

## The fix

The architecture did not change — classify, server decides, gate enforces. The classifier grew a second layer:

- **Per-verb argument rules** for the dangerous read-verbs (find, sed, awk, sort, uniq, journalctl, date, crontab) and a dedicated git pricer that distinguishes list forms from writes per subcommand.
- **The full bash separator set** — newlines and bare `&` split commands exactly as the shell does.
- **Substitution pricing** — inner commands are classified too; the strictest class wins; unparseable substitution fails closed.
- **Honest redirects** — `2>` and `&>` to a real file are writes. One carve-out, set by evidence (below): redirects to `/dev/null` are discards, not writes.
- **Destructive parity** — `rm` in all forms, `shred`, `truncate`, `dd` writing anywhere, `git clean`, `git reset --hard`, and `find -delete` are labeled destructive.
- **Per-part fallback grants** — a grant authorizes only the part of a command its pattern actually matches.
- **A doctrine, recorded in the code:** *destructive never goes through the gate.* A destructive-classified command is denied at the gate itself, before any grant is consulted. (The battery had shown explicit destructive grants were unreachable in the previous code — an ambiguity we resolved by making the hard-deny deliberate and documented rather than accidental.)

## Verification — three independent checks

1. **The battery, re-run on the candidate:** 0 failures on all four profiles, 0 under-classified, 0 false denies. The old classifier's 10 false-deny verdicts on benign commands (path-prefixed reads, `crontab -l`, process-substitution diffs) are also fixed.
2. **The lockout replay.** Before deployment we replayed 562 real commands the production gate had actually allowed (from its own audit log) through the candidate. The realistic failure mode of a hardening fix is locking the operator's own agent out of its daily work; the replay showed **0 lockouts**. It also caught an over-correction in our first candidate: pricing `2>/dev/null` as a write would have mislabeled 53 real read commands and overcharged them on the pay-per-use path — that evidence is why `/dev/null` discards are exempt.
3. **Deployment discipline.** Rollback tag created before any change; the previous production file preserved on the server under a dated backup name and hash-verified; candidate smoke-tested on the server before the swap; after the swap, the battery was re-run against the file fetched back from production (0 failures), and a live destructive command issued through the real SSH gate was denied with the doctrine message — nothing executed.

Two process moments are worth recording because they are the method working as intended. The battery caught a defect *in our own fix* — a missing comma in the pattern list silently fused two patterns and disabled a protection; the tests found it before deployment. And after deployment, the hardened gate denied the operator's own repository commit because the commit *message* contained the words "reset --hard" — the classifier prices text, and text about destructive commands prices destructive. We left the pattern strict and committed from a message file instead. The safe direction won over convenience, on the record.

## Limitations, stated plainly

Shell classification is heuristic and always will be; the command language is infinite. The defensible end state is not "the classifier is perfect" — it is:

- every attack class we know is in the battery, blocked, and regression-locked (the corpus and harness ship with this case study and gate every future classifier change);
- anything the classifier does not recognize is *unclassified*, which no customer grant covers — the unknown fails closed;
- classification is only the pricing step: authorization is still a cryptographic check against a human-issued grant on the UCII server, and revocation (case study 002) removes the grant regardless of what any command is priced.

## Artifacts

- Battery corpus + harness: `tests/classifier-battery/` in this repository (127 items, four profiles, verdict-only).
- Rollback tag: `rollback-pre-classifier-fix-20261023`.
- Deployed gate SHA-256 (production): `616a6e07…21ef7`. Public repository gate SHA-256: `55d0825f…5849` (comment wording differs for publication; classifier logic identical, battery-verified).
