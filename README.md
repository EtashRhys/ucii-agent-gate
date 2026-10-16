# UCII Agent Gate

Give your AI agent SSH access to your server **without giving it the keys
to the kingdom.** The gate is a tiny forced-command wrapper: every
command your agent tries to run is classified, checked against your
policy (identity + entitlement + rules), logged for audit, and only then
executed — or denied.

Built for the "fired laptop" workflow: you chat with your AI from your
phone, it drives your server over SSH, and UCII governs what it's
allowed to do. The AI proposes. Your policy decides.

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
phone chat → AI agent → SSH → ┌─────────────┐ → your server
                              │  gate.py    │
                              │ 1. classify │
                              │ 2. policy   │ → audit.log (every decision)
                              │ 3. allow / deny
                              └─────────────┘
```

- **Classify:** `read`, `git`, `file-op`, `service`, `destructive`,
  `unclassified`. Destructive patterns are checked first and can never
  hide inside a longer command.
- **Policy** (`policy.json`): who the agent is, what entitlement it
  holds, what rules apply, and time-boxed explicit grants you issue.
- **Audit** (`audit.log`): one JSON line per decision — timestamp,
  agent, UCII identity id, command, class, allow/deny, reason.
- **Fail closed:** anything without an entitlement or matching rule is
  denied. Verifier errors deny too — never fail open.

## Packages: how the agent pays (or doesn't)

| Package | For | How |
|---|---|---|
| **Owner** (this repo's default) | You, on your own system | Full entitlement, no payment. Destructive needs your explicit grant. |
| **Entitlement** (`packages/entitlement/`) | Customers, flat-rate | Monthly/yearly subscription. Scoped classes + repos, expiry enforced. |
| **x402** (`packages/x402/`) | Sophisticated devs, pay-per-use | USDC micropayment per command class, verified via facilitator. Dry-run included. |

## Safety

- Nothing touches `sshd_config`. The gate is one `command="..."` prefix
  in `authorized_keys`.
- **Rollback = delete that line.** One line, instant.
- Your existing keys keep working untouched — the gate is additive.
- Destructive commands need an explicit, time-boxed grant from the
  owner, issued in plain chat and recorded in `policy.json`.

## UCII identity

Bind the gate to a real UCII `AI_AGENT` identity (post-quantum
ML-DSA signatures via [ucii-core](https://github.com/EtashRhys/ucii-core)):

```bash
python3 scripts/register_identity.py --name "My deploy agent" --out identity.json
```

The identity id is written into every audit line.

## Files

- `gate.py` — the gate (single file, stdlib only)
- `install.sh` — one-command installer
- `policy.example.json` — starter policy
- `packages/entitlement/` — flat-rate subscription package
- `packages/x402/` — pay-per-use package + verifier
- `scripts/register_identity.py` — UCII AI_AGENT registration
