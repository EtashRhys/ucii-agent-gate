#!/usr/bin/env python3
"""Verify an agent's UCII wrapping end-to-end.

Signs a fresh message with the agent's ML-DSA-65 key and calls the
delegated check endpoint for each operation. All should return
authorized=True, state=ACTIVE.

Usage:
    python3 scripts/verify_wrapping.py --identity-id <uuid> \\
        [--credential ucii_credential.json] [--server http://127.0.0.1:8000]
"""
import argparse
import base64
import json
import sys
import urllib.request

sys.path.insert(0, "/opt/ucii/UCII/.venv/lib/python3.12/site-packages")
import oqs

OPERATIONS = [
    "ssh.exec:read",
    "ssh.exec:git",
    "ssh.exec:file-op",
    "ssh.exec:service",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--identity-id", required=True)
    ap.add_argument("--credential", default="ucii_credential.json")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    args = ap.parse_args()

    cred = json.load(open(args.credential))
    if cred.get("identity_id") != args.identity_id:
        raise SystemExit("credential identity_id does not match --identity-id")

    with oqs.Signature(
        "ML-DSA-65", base64.b64decode(cred["private_key_b64"])
    ) as sig:
        message = f"wrap-verify:{args.identity_id}".encode()
        signature = sig.sign(message)

    ok = True
    for op in OPERATIONS:
        body = json.dumps({
            "identity_id": args.identity_id,
            "credential_fingerprint": cred["credential_fingerprint"],
            "message": message.decode(),
            "signature": base64.b64encode(signature).decode(),
            "operation": op,
        }).encode()
        req = urllib.request.Request(
            args.server.rstrip("/") + "/v1/authorization/delegated/check",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = json.load(urllib.request.urlopen(req, timeout=15))
            good = resp.get("authorized") and \
                resp.get("authority_state") == "ACTIVE"
            print(f"{op}: authorized={resp.get('authorized')} "
                  f"state={resp.get('authority_state')}")
            ok = ok and good
        except Exception as e:
            print(f"{op}: FAILED: {e}")
            ok = False

    print("OK - all operations authorized" if ok else "MISMATCH - investigate")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
