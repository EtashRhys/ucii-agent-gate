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

There is nothing to renew on your end. Your agent's authority is
ACTIVE until revoked — no expiry date, no new package, no
re-install, ever.

The monthly flow, from the operator's side:

- **You pay** → nothing happens. The grant stays active, your agent
  keeps working.
- **You stop paying** → the operator revokes that one authority.
  From that second, every command is denied.

That's the entire renewal model. The credentials you received on day
one are the last ones you'll ever need.

## Suggested scope defaults

| | Monthly | Yearly |
|---|---|---|
| Command classes | read, git, file-op | read, git, file-op, service |
| Repo scope | 1 repo | org-wide |
| Destructive | deny (grant per-case) | deny (grant per-case) |

## What you're buying: the authority lifecycle

This is the part that makes the gate worth paying for. Here's exactly
how authority works, in plain language.

**Grant — specific, never blanket.** When your subscription activates,
the server owner grants your agent a *delegated authority*: a signed
record naming the exact operations your agent may perform (for
example: read files, run git, manage services). There are no
wildcards — every permitted operation is listed by name. Anything not
listed is denied. The grant is active the moment the owner approves it.

**Authorization — checked on every command.** Each time your agent
runs a command, the gate classifies it (read, git, file operation,
service, destructive, unknown) and asks the UCII server: *does this
agent hold an active authority covering this operation?* The request
is cryptographically signed with your agent's post-quantum credential,
so it can't be forged. The server decides; the gate enforces. If the
server can't be reached, the gate denies — it never fails open.

**Revoke — one grant, deliberately.** The owner can revoke a single
authority at any time, stating a reason. Revocation is immediate:
from that moment, every command under that grant is denied. You can't
revoke "everything" with one vague action — each revocation names one
exact authority, so it's always clear what was cut and why.

**Re-grant — no quiet undo.** A revoked authority stays revoked,
permanently. There is no "un-revoke." If access needs to be restored,
the owner issues a brand-new grant with a new ID. That means every
restoration is a fresh, logged event with the owner's name on it —
nobody can silently switch your agent back on.

In short: authority is granted specifically, checked constantly,
revoked deliberately, and never restored without a trace.

## Pricing & payment

| Plan | Price |
|---|---|
| Monthly | **$49 CAD/month per agent** |
| Yearly | **$490 CAD/year per agent** (two months free) |

Payment is by **Interac e-Transfer** (Canada):

1. Send your transfer to **bradphee@gmail.com**.
2. Put your **agent name** in the transfer message/reference.
3. The owner verifies receipt and provisions your agent's subscription.
   Monthly activates on receipt; yearly activates for 12 months.

No payment processor, no account to create, no per-command metering.
You pay, your agent gets wrapped, the gate enforces your scopes.

## Renewal

There is nothing to renew on your end. Your agent's authority is
ACTIVE until revoked — no expiry date, no new package, no
re-install, ever.

The monthly flow, from the operator's side:

- **You pay** → nothing happens. The grant stays active, your agent
  keeps working.
- **You stop paying** → the operator revokes that one authority.
  From that second, every command is denied.

That's the entire renewal model. The credentials you received on day
one are the last ones you'll ever need.
