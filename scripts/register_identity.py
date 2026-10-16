#!/usr/bin/env python3
"""
Register a UCII AI_AGENT identity for the gate.

Usage:
    python3 scripts/register_identity.py --name "My deploy agent" --out identity.json

Requires ucii-core on the PYTHONPATH (pip install ucii-core, or point at
a checkout). Falls back to a locally-generated identity record if
ucii-core is unavailable — the gate works either way; UCII just makes
the identity cryptographic and portable.
"""
import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--name", required=True)
parser.add_argument("--out", default="identity.json")
args = parser.parse_args()

identity = None
try:
    from ucii import Identity, IdentityType
    ident = Identity(name=args.name, identity_type=IdentityType.AI_AGENT)
    identity = {
        "id": str(getattr(ident, "id", "")),
        "name": ident.name,
        "type": getattr(ident.identity_type, "value", "AI_AGENT"),
        "provider": "ucii-core",
    }
    # Attach public key material when the model exposes it.
    for attr in ("public_key", "verifying_key", "did"):
        if hasattr(ident, attr):
            v = getattr(ident, attr)
            identity[attr] = v.hex() if isinstance(v, bytes) else str(v)
    print("Registered UCII AI_AGENT identity via ucii-core.")
except Exception as e:
    print("ucii-core unavailable (%s); writing local identity record." % e)

if identity is None:
    import hashlib
    import time
    seed = ("%s|%s" % (args.name, time.time())).encode()
    identity = {
        "id": "local-" + hashlib.sha256(seed).hexdigest()[:16],
        "name": args.name,
        "type": "AI_AGENT",
        "provider": "local",
    }

with open(args.out, "w") as f:
    json.dump(identity, f, indent=2)
print("Wrote %s (id=%s)" % (args.out, identity["id"]))
