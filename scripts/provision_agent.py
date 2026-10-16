#!/usr/bin/env python3
"""Provision a UCII AI_AGENT identity via the operator flow.

Creates the identity, registers the ML-DSA-65 credential, sets up the
service entitlement, and issues the (encrypted) controller authority —
atomically. Must run with sudo (systemd host key is root-only) and with
DATABASE_URL pointing at the PRODUCTION database.

Usage:
    sudo DATABASE_URL="sqlite:////var/lib/ucii/database/pq_auth.db" \\
        python3 scripts/provision_agent.py \\
        --name "Agent Name" \\
        --description "What this agent does" \\
        --public-key agent_public_key.b64 \\
        [--granted-by operator-handle]
"""
import argparse
import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, "/opt/ucii/UCII/src")
sys.path.insert(0, "/opt/ucii/UCII/.venv/lib/python3.12/site-packages")

from pq_auth.identity.schemas import IdentityCreate
from pq_auth.identity.models import IdentityType
from ucii_agents.external_signer_operator_provisioning import (
    provision_external_signer_operator_identity,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--description", default="")
    ap.add_argument("--public-key", required=True,
                    help="base64-encoded ML-DSA-65 public key file")
    ap.add_argument("--granted-by", default="operator")
    ap.add_argument("--output-dir", default="/opt/ucii/ucii-agent-gate",
                    help="where to write controller_authority.enc")
    args = ap.parse_args()

    pub = base64.b64decode(Path(args.public_key).read_text().strip())
    fingerprint = hashlib.sha256(pub).hexdigest()
    slug = "".join(
        c if c.isalnum() else "-" for c in args.name.lower()
    ).strip("-")

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    enc_path = out / "controller_authority.enc"
    if enc_path.exists():
        raise SystemExit(
            f"refusing to overwrite {enc_path} — "
            "back it up or remove it first"
        )

    result = provision_external_signer_operator_identity(
        identity_data=IdentityCreate(
            identity_type=IdentityType.AI_AGENT,
            name=args.name,
            description=args.description,
        ),
        public_key=pub,
        fingerprint=fingerprint,
        allowed_operations=["POST /v1/authorization/delegated/check"],
        controller_authority_output=enc_path,
        issued_by=args.granted_by,
    )
    print(f"identity_id: {result.identity_id}")
    print(f"controller authority: {enc_path} (root-only, mode 600)")
    print("OK")


if __name__ == "__main__":
    main()
