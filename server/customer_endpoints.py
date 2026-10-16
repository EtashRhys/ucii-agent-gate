"""
Reference implementation: customer-scoped delegated authority endpoints.

STEP 1 DRAFT — review only. Nothing here touches the production server.
Implements the UI contract in ui/API-CONTRACT.md using Option B:
the lifecycle daemon exposes customer-scoped operations, and these
endpoints verify the human's control secret + enforce policy rails before
calling the daemon. The daemon remains the SINGLE write path for authority
records — no direct DB writes from these endpoints.

Endpoints drafted:
  GET  /v1/authorization/delegated/{authority_id}                (status)
  POST /v1/authorization/delegated/{authority_id}/customer-revoke (kill)
  POST /v1/authorization/delegated/{authority_id}/replace         (replace)
  GET  /v1/authorization/delegated/authorities                   (operator list)

Design decisions (Brad-approved):
- The customer proves they are the HUMAN via a control secret issued at
  onboarding. It lives in the human's credentials email, never on the
  agent's server. The agent knows its own authority ID from check responses,
  so the ID alone authorizes view-only — kill/replace require the secret.
- Policy rails are enforced here, server-side, never trusted to the UI:
  destructive is never grantable; replace can only pick from the product's
  operation classes.
- The existing operator grant/revoke endpoints are UNCHANGED. They keep
  requiring operator lifecycle authorization. These are a separate,
  narrower door.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Imports below reference the real UCII modules. In this draft they are
# illustrative — wire them when this moves to the server (Step 3+).
# ---------------------------------------------------------------------------
# from ..config import get_db
# from .models import ActionAuthority, ActionAuthorityStatus
# from ucii_agents.provenance_recorder import ProvenanceRecorder

router = APIRouter(
    prefix="/v1/authorization/delegated",
    tags=["delegated-authority-customer"],
)

# ---------------------------------------------------------------------------
# Policy rails (Brad's — enforced here, not in the UI)
# ---------------------------------------------------------------------------

# The only operation classes a customer may grant. Destructive is deliberately
# absent: it is never a standing grant, only the scoped $25 / 2-hour flow.
CUSTOMER_GRANTABLE_OPERATIONS = frozenset({
    "ssh.exec:read",
    "ssh.exec:git",
    "ssh.exec:file-op",
    "ssh.exec:service",
})

# scrypt params for control-secret hashing (same rationale as the vault:
# stdlib, N=2^15/r=8 needs maxmem raised past OpenSSL's 32MB default).
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**15, 8, 1
_SCRYPT_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * _SCRYPT_P * 2


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AuthorityStatusResponse(BaseModel):
    authority_id: str
    identity_id: str
    authority_state: str
    allowed_operations: list[str]
    granted_at: datetime | None = None
    last_seen: datetime | None = None  # TODO: wire from audit log (Step 3)


class CustomerRevokeRequest(BaseModel):
    control_secret: str
    reason: str = "customer kill switch"


class ReplaceGrantRequest(BaseModel):
    control_secret: str
    allowed_operations: list[str]


class ReplaceGrantResponse(BaseModel):
    old_authority_id: str
    authority_id: str  # the NEW grant
    identity_id: str
    authority_state: str
    allowed_operations: list[str]
    # NOTE: the control secret carries over to the new authority.
    # The customer keeps using the same secret — one secret per customer
    # relationship, not per grant. Simpler, and rotation is a support task.


# ---------------------------------------------------------------------------
# Control secret store (DRAFT model — new table, Step 2)
# ---------------------------------------------------------------------------
#
# class CustomerControlSecret(Base):
#     """One human-held secret per authority. Issued at grant time.
#
#     The plaintext secret is delivered in the human's credentials email and
#     NEVER stored. Only the scrypt hash lives here. The agent's server never
#     sees it — it is not part of the agent's credential package.
#     """
#     __tablename__ = "customer_control_secrets"
#
#     authority_id = Column(String, ForeignKey("action_authorities.id"),
#                           primary_key=True)
#     secret_hash = Column(String, nullable=False)  # scrypt(secret, salt)
#     secret_salt = Column(String, nullable=False)
#     created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
#     # v2: customer_id → one secret for all their authorities (fewer secrets
#     # to manage). v1 is per-authority: matches the UI, minimal new state.


def _hash_secret(secret: str, salt: bytes) -> str:
    return hashlib.scrypt(
        secret.encode(), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=32, maxmem=_SCRYPT_MAXMEM,
    ).hex()


def issue_control_secret() -> tuple[str, str, str]:
    """Generate a fresh control secret. Returns (plaintext, hash, salt_hex).

    The plaintext goes into the human's credentials email. ONLY the hash is
    stored. Call this at grant time (modification to the existing grant flow
    — Step 2/3).
    """
    plaintext = "ucs_" + os.urandom(24).hex()
    salt = os.urandom(16)
    return plaintext, _hash_secret(plaintext, salt), salt.hex()


def verify_control_secret(db: Session, authority_id: str, secret: str) -> bool:
    """Constant-time check of the human's control secret for one authority."""
    # TODO (Step 2): query CustomerControlSecret by authority_id.
    # row = db.query(CustomerControlSecret).filter_by(authority_id=authority_id).first()
    # if row is None: return False
    # candidate = _hash_secret(secret, bytes.fromhex(row.secret_salt))
    # return hmac.compare_digest(candidate, row.secret_hash)
    raise NotImplementedError("wire to CustomerControlSecret table (Step 2)")


def _get_active_authority(db: Session, authority_id: str):
    """Fetch the authority or 404. Callers check status themselves."""
    # TODO (Step 3): from .models import ActionAuthority
    # authority = db.query(ActionAuthority).filter_by(id=authority_id).first()
    # if authority is None:
    #     raise HTTPException(status.HTTP_404_NOT_FOUND, "authority not found")
    # return authority
    raise NotImplementedError("wire to ActionAuthority (Step 3)")


def _enforce_rails(allowed_operations: list[str]) -> None:
    """Server-side policy enforcement. The UI is never trusted."""
    if not allowed_operations:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "grant must allow at least one operation")
    bad = set(allowed_operations) - CUSTOMER_GRANTABLE_OPERATIONS
    if bad:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"not grantable via customer self-serve: {sorted(bad)}",
        )


# ---------------------------------------------------------------------------
# Daemon contract — Option B (TODO: implement in the lifecycle daemon, Step 3+)
# ---------------------------------------------------------------------------
#
# The daemon exposes two new customer-scoped operations. They write through
# the SAME protected path as operator grant/revoke (provenance recorded,
# same tables) — the daemon is what verifies scope, not these endpoints.
#
#   daemon.customer_revoke(*, authority_id, reason, provenance) -> None
#       Marks the authority REVOKED (revoked_at, revocation_reason).
#       Fails if already revoked.
#
#   daemon.customer_replace(*, authority_id, allowed_operations, provenance)
#       -> new_authority_id
#       Atomically: marks old REVOKED (reason "replaced by customer") and
#       creates the new ACTIVE grant for the SAME subject_identity_id.
#       Rejects any operation outside the daemon's own copy of the rails
#       (defense in depth: enforced here AND in the daemon).
#
# from ucii_agents.controller_lifecycle_client import (
#     ProtectedControllerLifecycleClient, ...
# )


# ---------------------------------------------------------------------------
# 1. Status (view-only — authority ID alone is enough)
# ---------------------------------------------------------------------------

@router.get(
    "/{authority_id}",
    response_model=AuthorityStatusResponse,
    summary="Customer view of one authority",
)
def customer_authority_status(authority_id: str, db: Session = Depends(None)):  # noqa: B008 — wire get_db in Step 3
    authority = _get_active_authority(db, authority_id)
    return AuthorityStatusResponse(
        authority_id=authority.id,
        identity_id=authority.subject_identity_id,
        authority_state=authority.status.value,
        allowed_operations=authority.allowed_operations,
        granted_at=authority.granted_at,
    )


# ---------------------------------------------------------------------------
# 2. Customer kill switch
# ---------------------------------------------------------------------------

@router.post(
    "/{authority_id}/customer-revoke",
    summary="Customer kill switch (human-held control secret)",
)
def customer_revoke(
    authority_id: str,
    request: CustomerRevokeRequest,
    db: Session = Depends(None),  # noqa: B008 — wire get_db in Step 3
):
    if not verify_control_secret(db, authority_id, request.control_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "bad control secret")
    authority = _get_active_authority(db, authority_id)
    if authority.status.value != "ACTIVE":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "authority is not active")
    # TODO (Step 3): call daemon.customer_revoke(...) — Option B.
    # The daemon marks REVOKED + records provenance via the protected path.
    raise NotImplementedError("wire daemon.customer_revoke (Step 3)")


# ---------------------------------------------------------------------------
# 3. Replace grant (revoke old + grant new, atomically — identity unchanged)
# ---------------------------------------------------------------------------

@router.post(
    "/{authority_id}/replace",
    response_model=ReplaceGrantResponse,
    summary="Customer replace-grant (human-held control secret)",
)
def customer_replace_grant(
    authority_id: str,
    request: ReplaceGrantRequest,
    db: Session = Depends(None),  # noqa: B008 — wire get_db in Step 3
):
    if not verify_control_secret(db, authority_id, request.control_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "bad control secret")
    _enforce_rails(request.allowed_operations)  # server-side, always
    authority = _get_active_authority(db, authority_id)
    if authority.status.value != "ACTIVE":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "authority is not active")
    # TODO (Step 3): call daemon.customer_replace(...) — Option B.
    # Atomic revoke-old + grant-new for the SAME subject_identity_id.
    # The control secret carries over (no new secret issued on replace).
    raise NotImplementedError("wire daemon.customer_replace (Step 3)")


# ---------------------------------------------------------------------------
# 4. Operator list (existing operator auth — page lives behind secret path)
# ---------------------------------------------------------------------------

@router.get(
    "/authorities",
    summary="Operator: list all authorities",
)
def operator_list_authorities(db: Session = Depends(None)):  # noqa: B008 — wire get_db in Step 3
    # TODO (Step 3): operator-authenticated (secret path at the serving layer
    # + existing operator checks). Returns id, identity, ops, granted_at,
    # last_seen, status for every authority.
    raise NotImplementedError("wire operator list (Step 3)")


# ---------------------------------------------------------------------------
# Grant-flow modification (Step 2/3) — issue the control secret at grant time
# ---------------------------------------------------------------------------
#
# In the existing POST /v1/authorization/delegated/grant handler, after the
# authority record is created:
#
#     plaintext, secret_hash, salt_hex = issue_control_secret()
#     db.add(CustomerControlSecret(
#         authority_id=new_authority.id,
#         secret_hash=secret_hash,
#         secret_salt=salt_hex,
#     ))
#
# The plaintext goes into the HUMAN's credentials email — alongside the
# authority ID, never alongside the agent's keypair files. The agent's
# server never receives it.
