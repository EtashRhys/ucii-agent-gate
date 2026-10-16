# UCII Agent Gate

Give your AI agent SSH access to your server **without giving it the keys
to the kingdom.** The gate is a tiny forced-command wrapper: every
command your agent tries to run is classified, checked against your
**UCII server** (identity + delegated authority, cryptographically
verified), logged for audit, and only then executed — or denied.

Built for the "fired laptop" workflow: you chat with your AI in plain
language, it drives your server over SSH, and UCII governs what it's
allowed to do. The AI proposes. Your server decides.

Not phone-specific. You talk to the agent from any device — phone,
laptop, whatever — and the agent itself can run anywhere: a cloud VM,
your laptop, a container. The gate lives on the *server*, so every SSH
command goes through the UCII check no matter where the agent sits.
No terminal required on your end, ever.

## The 3-step install

```bash
curl -sSL https://raw.githubusercontent.com/EtashRhys/ucii-agent-gate/main/install.sh | bash
```

Then append the one `authorized_keys` line it prints to your server.
Done. Test:

```bash
ssh -i ~/.ssh/ucii_agent_gate user@server 'uptime'        # allowed
ssh -i ~/.ssh/ucii_agent_gate user@server 'rm -rf /tmp/x' # denied + logged
```

## How it works

```
phone chat → AI agent → SSH → ┌─────────────┐    ┌──────────────┐
                              │  gate.py    │───▶│ UCII server  │
                              │ 1. classify │    │ delegated    │ → audit.log
                              │ 2. UCII ask │◀───│ check (ML-   │ (every decision)
                              │ 3. allow /  │    │ DSA signed)  │
                              │    deny     │    └──────────────┘
                              └─────────────┘
```

- **Classify:** `read`, `git`, `file-op`, `service`, `destructive`,
  `unclassified`. Destructive patterns are checked first and can never
  hide inside a longer command.
- **UCII check:** every command is sent to your UCII server's
  `/v1/authorization/delegated/check`, signed with the agent's
  post-quantum ML-DSA-65 credential. The **server** decides; the gate
  enforces. This endpoint is free (not x402-metered).
- **Local fallback:** if the server is unreachable, the gate falls back
  to `policy.json` **only** for the owner entitlement — and logs the
  fallback. Everyone else fails closed.
- **Audit** (`audit.log`): one JSON line per decision — timestamp,
  agent, UCII identity id, command, class, allow/deny, reason, and
  whether the decision came from the UCII server or local policy.
- **Fail closed:** anything without an entitlement or matching rule is
  denied. Verifier errors deny too — never fail open.

## Wrapping an agent (joining the UCII family)

The gate is only half the story. Before it can ask your UCII server,
the agent needs a real UCII identity — that's called **wrapping**.
See **[ONBOARDING.md](ONBOARDING.md)** for the full guide, or run the
interactive wrapper on your UCII server:

```bash
sudo bash scripts/wrap-agent.sh
```

It walks you through keypair generation, identity provisioning,
lifecycle-service build, delegated grant, and verification — pausing
for your approval at each consequential step. Six steps, one command.

**Highly recommended:** have an AI agent go through this repo with you.
The wrapping involves server work, approval decisions, and a few gotchas
that are easier spotted in pairs — an agent reading these docs alongside
you makes the whole thing dramatically easier than going solo. (That is
how the first agent was wrapped.)

## Packages: how the agent pays (or doesn't)

| Package | For | How |
|---|---|---|
| **Owner** (this repo's default) | You, on your own system | Full entitlement, no payment. Destructive needs your explicit grant. |
| **Entitlement** (`packages/entitlement/`) | Customers, flat-rate | Monthly/yearly subscription. Scoped classes + repos, expiry enforced. |
| **x402** (`packages/x402/`) | Sophisticated devs, pay-per-use | USDC micropayment per command class, verified via facilitator. Dry-run included. |

## Safety

- Nothing touches `sshd_config`. The gate is one `command="..."`
  prefix in `authorized_keys`.
- **Rollback = delete that line.** One line, instant.
- Your existing keys keep working untouched — the gate is additive.
- Destructive commands need an explicit, time-boxed grant from the
  owner, issued in plain chat — never baked into a standing grant.
- For UCII identity operations, the operator approves each step. The
  agent never self-provisions, never self-grants.

## Files

- `gate.py` — the gate (UCII-authority edition)
- `install.sh` — one-command installer
- `ONBOARDING.md` — the complete agent-wrapping guide
- `policy.example.json` — starter local policy (owner fallback)
- `packages/entitlement/` — flat-rate subscription package
- `packages/x402/` — pay-per-use package + verifier
- `scripts/wrap-agent.sh` — interactive agent wrapping (easiest path)
- `scripts/provision_agent.py` — operator identity provisioning
- `scripts/build_lifecycle_service.py` — per-agent lifecycle service
- `scripts/grant_authority.py` — delegated authority grant
- `scripts/verify_wrapping.py` — end-to-end wrapping verification
- `scripts/register_identity.py` — public x402 AI_AGENT registration
