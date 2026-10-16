# UI API contract

What the control-panel pages call, endpoint by endpoint. Serve both pages
same-origin with the API (no CORS issues).

**Status key:** EXISTS = live on the UCII server today. NEEDS ADDING = the UI
is written against it, but the server doesn't have it yet — the pages say so
plainly instead of failing silently.

## Customer panel (`customer-panel.html`)

| # | Method | Path | Purpose | Status |
|---|--------|------|---------|--------|
| 1 | GET | `/v1/authorization/delegated/{authority_id}` | Authority status: state, ops, granted_at, last_seen, identity_id | NEEDS ADDING |
| 2 | POST | `/v1/authorization/delegated/{authority_id}/replace` | Revoke old + grant new atomically. Body: `{allowed_operations: [...]}`. Returns new `authority_id`. Identity unchanged. | NEEDS ADDING |
| 3 | POST | `/v1/authorization/delegated/{authority_id}/customer-revoke` | Customer kill switch. Body: `{reason}`. Scoped to that one authority; no operator lifecycle auth required. | NEEDS ADDING |
| 4 | — | destructive window checkout | $25 / 2-hour / one-command scoped grant | NEEDS ADDING (product flow, not just an endpoint) |

Why new endpoints instead of the existing ones: `POST
/v1/authorization/delegated/grant` and `POST
/v1/authorization/delegated/{authority_id}/revoke` both consume
root-controlled **operator lifecycle authorization** from server custody —
a customer calling them gets 403 by design. The customer endpoints above
are authenticated by the authority ID itself (v1) and later by the human's
UCII identity via `HumanGovernanceRelationship` (v2). Blast radius of a
leaked authority ID: someone can stop *your own* agent. They can't widen,
impersonate, or touch anyone else.

## Operator panel (`operator-panel.html`)

| # | Method | Path | Purpose | Status |
|---|--------|------|---------|--------|
| 5 | GET | `/v1/authorization/delegated/authorities` | List all authorities (operator-authenticated server side; only reachable via the secret path) | NEEDS ADDING |
| 6 | POST | `/v1/authorization/delegated/{authority_id}/revoke` | Revoke one authority. Body: `{reason}` | EXISTS |

## Auth model

- **Customer (v1):** the authority ID from the credentials package. Bearer-style,
  scoped to that single authority.
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
