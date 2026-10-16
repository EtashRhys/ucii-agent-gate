# Package: Flat-rate entitlement (monthly / yearly)

The simple option. The server owner grants an AI agent a subscription
entitlement: full access within agreed scopes, billed flat monthly or
yearly. No per-command payments, no crypto wallets for the agent.

## How it works

1. The owner adds the agent to `policy.json`:

```json
"agents": {
  "customer-agent-1": {
    "entitlement": "subscriber-monthly",
    "expires_at": "2026-11-15T00:00:00+00:00",
    "scopes": {
      "classes": ["read", "git", "file-op", "service"],
      "repos": ["myorg/*"]
    }
  }
}
```

Use `"subscriber-yearly"` for annual billing — the gate treats both the
same; the label is for your billing records.

2. The agent's key goes in `authorized_keys` with the
`command="...gate.py"` prefix (see install.sh).

3. The gate allows only the classes in `scopes.classes`, and for `git`
additionally restricts to `scopes.repos` (supports `*` wildcards).
Everything else is denied and logged.

## Renewal

Update `expires_at`. That's the entire renewal flow — one line, no
key rotation, no re-install. An expired subscription fails closed:
the gate denies every command with "subscription expired" until renewed.

## Suggested scope defaults

| | Monthly | Yearly |
|---|---|---|
| Command classes | read, git, file-op | read, git, file-op, service |
| Repo scope | 1 repo | org-wide |
| Destructive | deny (grant per-case) | deny (grant per-case) |

## Pricing & payment

| Plan | Price |
|---|---|
| Monthly | **$49 CAD/month** |
| Yearly | **$490 CAD/year** (two months free) |

Payment is by **Interac e-Transfer** (Canada):

1. Send your transfer to **bradphee@gmail.com**.
2. Put your **agent name** in the transfer message/reference.
3. The owner verifies receipt and provisions your agent's subscription.
   Monthly activates on receipt; yearly activates for 12 months.

No payment processor, no account to create, no per-command metering.
You pay, your agent gets wrapped, the gate enforces your scopes.

## Renewal

The owner updates `expires_at` when your next payment arrives. That's
the entire renewal flow — one line, no key rotation, no re-install.
An expired subscription fails closed: the gate denies every command
with "subscription expired" until renewed.
