# UI API contract

What the control-panel pages call, endpoint by endpoint. Serve both pages
same-origin with the API (no CORS issues).

**Status key:** EXISTS = live on the UCII server today. NEEDS ADDING = the UI
is written against it, but the server doesn't have it yet — the pages say so
plainly instead of failing silently.

## Auth model (read this first)

The customer proves they are the **human**, not the agent. The agent learns
its own authority ID from check responses, so the authority ID alone is not
enough for kill/replace — a compromised agent holding it could widen itself.

- **Customer (v1):** a control secret issued at onboarding, delivered in the
  human's credentials email, **never placed on the agent's server**. The agent
  never sees it. Kill and replace require it. View needs only the authority
  ID (read-only, harmless).
- **Customer (v2):** the human's UCII identity signature, authorized through
  the existing `HumanGovernanceRelationship` (`GRANT_DELEGATED_AUTHORITY` /
  `REVOKE_DELEGATED_AUTHORITY`). This is where the identity-vault web sign-in
  plugs in.
- **Operator (v1):** page served at an unguessable secret path generated at
  install. Revoke calls use the existing operator lifecycle auth, unchanged.

Blast radius of a leaked control secret: someone can stop or reconfigure
*your own* agent within the policy rails. They can't widen beyond the rails,
can't touch anyone else's agent, can't grant a standing hall pass.

## Customer panel (`customer-panel.html`)

| # | Method | Path | Purpose | Status |
|---|--------|------|---------|--------|
| 1 | GET | `/v1/authorization/delegated/{authority_id}` | Authority status: state, ops, granted_at, last_seen, identity_id | NEEDS ADDING |
| 2 | POST | `/v1/authorization/delegated/{authority_id}/replace` | Revoke old + grant new atomically. Control-secret authed. Body: `{allowed_operations: [...]}`. Returns new `authority_id`. Identity unchanged. Server enforces policy rails. | NEEDS ADDING |
| 3 | POST | `/v1/authorization/delegated/{authority_id}/customer-revoke` | Customer kill switch. Control-secret authed. Body: `{reason}`. Scoped to that one authority; no operator lifecycle auth required. | NEEDS ADDING |
| 4 | — | hall pass checkout | $25 / 2-hour / one specific command, UCII Admin approves | NEEDS ADDING (product flow, not just an endpoint) |

Why new endpoints instead of the existing ones: `POST
/v1/authorization/delegated/grant` and `POST
/v1/authorization/delegated/{authority_id}/revoke` both consume
root-controlled **operator lifecycle authorization** from server custody —
a customer calling them gets 403 by design, and that must not change.
The customer endpoints are a separate, narrower door: same blast radius
as the customer's own intent, nothing more.

## Operator panel (`operator-panel.html`)

| # | Method | Path | Purpose | Status |
|---|--------|------|---------|--------|
| 5 | GET | `/v1/authorization/delegated/authorities` | List all authorities (operator-authenticated server side; only reachable via the secret path) | NEEDS ADDING |
| 6 | POST | `/v1/authorization/delegated/{authority_id}/revoke` | Revoke one authority. Body: `{reason}` | EXISTS |

## Auth model

- **Customer (v1):** the control secret from the credentials package (human-held,
  never on the agent's server). View needs only the authority ID.
- **Customer (v2):** human UCII identity sign-in; authorization via the existing
  `HumanGovernanceRelationship` (`GRANT_DELEGATED_AUTHORITY` /
  `REVOKE_DELEGATED_AUTHORITY`).
- **Operator (v1):** page served at an unguessable secret path generated at
  install. The revoke call itself uses the existing operator lifecycle auth.
- **Operator (v2):** UCII-signed operator sessions (arrives with the vault's
  web sign-in).

## Policy rails (enforced server-side, not in the pages)

- Destructive is never a standing grant.
- Replace-grant can only pick from the product's operation classes.
- The gate keeps checking every command against the server; these pages change
  *grants*, never *checks*.
