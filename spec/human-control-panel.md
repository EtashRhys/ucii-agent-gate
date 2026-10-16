# Human Control Panel — spec

Version: 1

## Purpose

After onboarding, the human customer manages their own agent's grants. Brad's job ends at onboarding + identity issuance + policy rails. Everything below is the customer operating their own controls — no operator involvement per action.

The model: **the operator grants, the customer manages.** The human is the principal, the agent is the delegate. The agent can never widen its own authority — that rule is unchanged and lives in the gate, not in this UI.

## What ships where

The UI is served by the UCII server itself — web pages, device-agnostic (phone, laptop, tablet, it's just a URL). It ships as part of the server install. No separate deployment, no app.

Two pages:

1. **Customer control panel** — the human managing their agent.
2. **Operator page** — Brad seeing every authority and revoking any of them.

## Page 1: Customer control panel

**Auth (v1):** the authority ID from the customer's credentials package. It's the control key — paste it, or open it from the link in the credentials email. If it leaks, the worst case is someone stops *your own* agent: no widening, no impersonation, no lateral movement.

**Auth (v2):** human UCII identity sign-in, authorized through the existing `HumanGovernanceRelationship` (`GRANT_DELEGATED_AUTHORITY` / `REVOKE_DELEGATED_AUTHORITY`). This is where the identity-vault web sign-in plugs in.

**View.** Agent name, identity ID, authority status (ACTIVE / REVOKED), granted operations, granted date, last-seen. Read-only, always visible.

**Replace grant.** The core flow — not kill, *replace*:
1. Customer picks operation classes for the new grant (read, git, file-op, service — bounded by the policy rails below).
2. One confirm: the old grant is revoked, the new grant is issued.
3. The identity stays the same. Only the grant changes.

Underneath, this is two existing calls back to back:
- `POST /v1/authorization/delegated/{authority_id}/revoke` `{"reason": "replaced by customer"}`
- `POST /v1/authorization/delegated/grant` `{"identity_id": ..., "allowed_operations": [...], "granted_by": <customer identity>}`

**Kill.** Revoke with a reason, one confirm, immediate. The agent stops on its next check. If they kill it, they kill it.

**Destructive window.** Destructive is never a standing grant — that's a policy rail, not a UI choice. The panel offers the existing scoped flow: $25, 2-hour window, one command. Self-serve through the panel; Brad doesn't hand-issue these.

## Page 2: Operator page

**Auth (v1):** secret-path token generated at server install. Unguessable URL, bookmarked. Rotation is one command.

**View.** Table of all authorities across all customers: agent name, customer, identity ID, granted operations, granted date, last-seen, status.

**Revoke.** One button per row, one confirm. Immediate, logged, irreversible — restoration is a new grant, per the standing rule.

Brad never needs this page for routine customer actions — customers manage themselves. It's the fire axe: abuse, non-payment, compromise.

## Policy rails (Brad's, enforced server-side — not UI suggestions)

- Destructive is never a standing grant. Only the scoped $25 / 2-hour / one-command flow.
- Customers can only grant operation classes the product offers. No custom classes, no escalation paths.
- The gate still checks every command against the UCII server. The panel changes *grants*; it doesn't bypass *checks*.
- Billing: the $49/month subscription covers the gating service and unlimited grant rotations. Mid-month kill: no refund — stated plainly at purchase. (Brad's policy call, recorded here.)

## Endpoint map (all exist today)

| Action | Endpoint |
|---|---|
| View status | `GET /v1/identity/{identity_id}` + authority state from `POST /v1/authorization/delegated/check` |
| Replace grant | revoke + grant (above) |
| Kill | `POST /v1/authorization/delegated/{authority_id}/revoke` |
| Operator revoke | same revoke endpoint, operator-authenticated |

## Deliberately out of v1

- Multi-agent dashboard (v1 is keyed by one authority ID; fleet view comes later).
- Customer-initiated narrowing below what they were granted — covered by replace-grant (issue a smaller grant).
- Human-readable audit log for the customer (the data exists server-side; the view doesn't yet).
