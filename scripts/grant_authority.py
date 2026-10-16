#!/usr/bin/env python3
"""Grant delegated authority to a UCII agent via its lifecycle socket.

The operator decides the scope. Must run with sudo (socket is group-
restricted). The grant is ACTIVE immediately.

Usage:
    sudo python3 scripts/grant_authority.py \\
        --socket /run/ucii-rocky-lifecycle/lifecycle.sock \\
        --operations ssh.exec:read ssh.exec:git ssh.exec:file-op ssh.exec:service \\
        --granted-by operator-handle
"""
import argparse
import sys

sys.path.insert(0, "/opt/ucii/UCII/src")
sys.path.insert(0, "/opt/ucii/UCII/.venv/lib/python3.12/site-packages")

from ucii_agents.controller_lifecycle_client import (
    ProtectedControllerLifecycleClient,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--operations", nargs="+", required=True)
    ap.add_argument("--granted-by", required=True)
    args = ap.parse_args()

    granted = ProtectedControllerLifecycleClient(
        socket_path=args.socket,
    ).grant_delegated_authority(
        allowed_operations=args.operations,
        granted_by=args.granted_by,
    )
    print(f"authority_id: {granted.authority_id}")
    print(f"identity_id: {granted.identity_id}")
    print(f"state: {granted.authority_state}")
    print(f"operations: {list(granted.allowed_operations)}")
    print("OK")


if __name__ == "__main__":
    main()
