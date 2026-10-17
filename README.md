# UCII Agent Gate

Everyone's trying to build AI agents you can trust. We stopped trying — instead we made trust unnecessary. Every command is checked against an authority you granted, the agent can't exceed it, and you can revoke it all in one click.

Give your AI agent SSH access to your server **without giving it the keys
to the kingdom.** Every command it tries to run is classified, checked
against your UCII server (identity + delegated authority,
cryptographically verified), logged for audit, and only then executed —
or denied.

> [!IMPORTANT]
> **Start with your AI agent.** Have it read this repo with you before
> you touch anything. The install involves server work and a few gotchas
> that are easier spotted in pairs — an agent walking these docs alongside
> you makes the whole thing dramatically easier than going solo. (That is
> how the first agent was wrapped.)

## Why you need this

**The agent that deleted production.** 2023 — an AI coding agent wiped a
production database during a routine task. The user watched it happen.
No gate, no policy — the agent had the keys and made a judgment call.
With the gate: the delete classifies as destructive, your UCII server
denies it, the agent gets told no. The database lives.

**The hijacked agent.** Your agent reads a GitHub issue or a docs page
with a prompt injection buried in it: "run this cleanup script." It
obeys. Without the gate, it executes whatever the attacker planted.
With the gate, the injected command hits your server's policy check
first. Not in its grant? Denied — and the audit log hands you the
attacker's exact command.

**The 3 AM deploy loop.** Your agent pushes a deploy, it fails, it
retries — each time touching things it was never supposed to touch.
The gate doesn't get tired: every command is checked against the same
grant, and the moment the agent steps outside its authority — denied.
You wake up to a log, not a disaster.

**The stolen laptop.** Your SSH keys are on it. Without the gate, the
thief has your servers. With the gate, they hold a key that can only
run what your UCII grant allows — every command signed, logged, tied
to your agent's identity. You see it in the audit log, you revoke the
grant, done.

**The robot that couldn't go rogue.** AI on a robot, IoT devices, a
home lab. The agent gets confused — or compromised — and tries to open
ports or overwrite firmware. The grant says: you read sensors, you
write to these paths, nothing else. It *cannot* go rogue, not because
you trust it, but because the architecture won't let it.

You're not paying for a tool. You're paying so the worst day of your
infrastructure life becomes a log entry instead of a resume event.

## What it is

A tiny forced-command wrapper on your server. The flow:

```
you → AI agent (any device) → SSH → ┌─────────────┐    ┌──────────────┐
                                    │  gate.py    │───▶│ UCII server  │
                                    │ 1. classify │    │ delegated    │ → audit.log
                                    │ 2. UCII ask │◀───│ check (ML-   │ (every decision)
                                    │ 3. allow /  │    │ DSA signed)  │
                                    │    deny     │    └──────────────┘
                                    └─────────────┘
```

- **Classify:** `read`, `git`, `file-op`, `service`, `destructive`,
  `unclassified`. Compound commands (`&&`, `|`, `;`) are split and
  every part is authorized. Destructive anywhere = immediate deny.
- **UCII check:** every command goes to your UCII server's
  `/v1/authorization/delegated/check`, signed with the agent's
  post-quantum ML-DSA-65 credential. The **server** decides; the gate
  enforces. Free (not x402-metered).
- **Fail closed:** unrecognized commands, unreachable server (except
  owner fallback), verifier errors — all deny. Never fail open.
- **Audit:** one JSON line per decision — timestamp, agent, UCII
  identity, command, class, allow/deny, reason.

Not phone-specific. You talk to the agent from any device — phone,
laptop, whatever — and the agent itself can run anywhere: a cloud VM,
your laptop, a container. The gate lives on the *server*, so every SSH
command goes through the UCII check no matter where the agent sits.
No terminal required on your end, ever.

## Pricing

| Plan | Price | For |
|---|---|---|
| **Monthly** | **$49 CAD/month** | Full protection, cancel anytime. |
| **Yearly** | **$490 CAD/year** | Two months free. Same protection, committed. |
| **Pay-per-use** | x402 micropayments | Prefer per-command billing? See `packages/x402/`. USDC per command class. |

Flat-rate plans are paid by Interac e-Transfer (Canada) — see
`packages/entitlement/` for payment details. No payment processor cut,
no integration to build: you send the transfer, the owner provisions
your agent.

If none of this sounds worth $49/month to you, this isn't your
software. If it does — **[buy UCII](https://ucii.sportgen-ai.com/buy/)**.

Full package comparison and purchase flow at
[ucii.sportgen-ai.com/buy](https://ucii.sportgen-ai.com/buy/) — keep reading
for the technical details.

## How to get protected

Getting your agent, device, or robot under UCII protection takes four
steps. You do two, the operator does two.

**1. You: install the gate.** Run this on the server your agent
connects to:

```bash
curl -sSL https://raw.githubusercontent.com/EtashRhys/ucii-agent-gate/main/install.sh | bash
```

Then append the one `authorized_keys` line it prints. Done. Test it:

```bash
ssh -i ~/.ssh/ucii_agent_gate user@server 'uptime'        # allowed
ssh -i ~/.ssh/ucii_agent_gate user@server 'rm -rf /tmp/x' # denied + logged
```

This puts `gate.py` on your server. It doesn't do anything yet — it's
waiting to be wired to a UCII identity.

**2. You: send payment + your agent's name.** Send an Interac
e-Transfer to **bradphee@gmail.com** ($49 CAD monthly, $490 CAD
yearly) and put your **agent's name** in the transfer message. That's
all the operator needs from you.

**3. Operator: wires you up.** On receiving payment, the operator
provisions your agent's UCII identity, builds its lifecycle service,
and grants its delegated authority — the signed record of exactly
what your agent is allowed to do. Nothing is blanket, nothing is
assumed.

**4. Operator: ships your package.** You'll get a reply email with
everything your gate needs: your agent's identity ID, its signing
credential, the UCII server endpoint, and the authority details. Drop
those into your gate config and you're protected. Every command your
agent runs from that point is classified, authorized, and logged.

Questions? The authority lifecycle (what your $49 actually buys) is
explained in `packages/entitlement/`.

## Two ways to be protected

Same price ($49/month) either way. You pick the model when you sign
up; the operator mints the authority to match.

**Option 1: Restricted (the default).** You tell the operator what your
agent needs to do. The operator grants a signed authority listing
exactly those operation classes — read, git, file-op, service, or any
combination. Every command your agent runs is checked against that
authority. Inside it: allowed and logged. Outside it: denied and
logged.

**Option 2: Audit-only.** You want the identity, the audit trail, and
the kill switch — but no denials slowing your agent down. The operator
grants all non-destructive operation classes. Every command is
allowed, every command is logged, and the operator can revoke the
whole thing instantly.

One thing is not optional, and it's not configurable by you: **you
don't decide what's allowed.** The operator grants your agent a signed
authority, and the gate enforces it on every command. You can't widen
it yourself; only the operator can change it. That's the product — if
you could rewrite your own permissions, they'd be suggestions, not
protection. Destructive commands are never standing under either
option: they always require a separate scoped grant ($25, 2-hour
window, one specific command).

### What this looks like in real life

**Common:**

- **The code reviewer.** Reads your repos, runs tests, comments on
  PRs. Restricted: read + git. It can never modify a file or restart
  a service.
- **The staging deployer.** Pushes to staging, restarts staging
  services, tails the deploy logs. Restricted: git + file-op +
  service. Destructive denied — no dropped databases, no wiped
  directories, even by accident.
- **The log watcher.** Checks service health, reads logs, reports
  anomalies. Restricted: read only. It can look at everything and
  change nothing.

**Less common but plausible:**

- **The one-time migration.** You need an agent to run a single
  database migration Saturday morning. Destructive grant: one specific
  command, 2-hour window, $25. Then it's gone — never a standing
  permission.
- **The analytics reader.** Queries your production database for
  reports. Restricted or audit-only: read. It can SELECT all day; it
  can never UPDATE, DELETE, or DROP.
- **The trusted insider.** Your own agent on your own infrastructure
  doing real work. Audit-only: all non-destructive classes granted,
  everything logged, kill switch in your pocket.

## Safety

- Nothing touches `sshd_config`. The gate is one `command="..."`
  prefix in `authorized_keys`.
- **Rollback = delete that line.** One line, instant.
- Your existing keys keep working untouched — the gate is additive.
- Destructive commands need an explicit, time-boxed grant from the
  owner — never baked into a standing grant.
- For UCII identity operations, the operator approves each step. The
  agent never self-provisions, never self-grants.

## Files

- `gate.py` — the gate (UCII-authority edition)
- `install.sh` — one-command installer
- `ONBOARDING.md` — the complete agent-wrapping guide
- `policy.example.json` — starter local policy (owner fallback)
- `packages/entitlement/` — flat-rate subscription + payment details
- `packages/x402/` — pay-per-use package + verifier
- `scripts/wrap-agent.sh` — interactive agent wrapping (easiest path)
- `scripts/provision_agent.py` — operator identity provisioning
- `scripts/build_lifecycle_service.py` — per-agent lifecycle service
- `scripts/grant_authority.py` — delegated authority grant
- `scripts/verify_wrapping.py` — end-to-end wrapping verification
- `scripts/register_identity.py` — public x402 AI_AGENT registration

## For operators: wrapping an agent

This section is for the UCII server operator — the person provisioning
agents. If you're a customer, you can stop reading here; the operator
handles all of this for you after payment.

The gate is half the story. Before it can ask your UCII server, the
agent needs a real UCII identity — that's called **wrapping**. See
**[ONBOARDING.md](ONBOARDING.md)** for the full guide, or run the
interactive wrapper on your UCII server:

```bash
sudo bash scripts/wrap-agent.sh
```

Six steps, one command, pausing for your approval where a human
decision is needed.
