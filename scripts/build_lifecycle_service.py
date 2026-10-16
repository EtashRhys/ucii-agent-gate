#!/usr/bin/env python3
"""Build a protected lifecycle service for a UCII agent.

Creates the system user + IPC group, the systemd-encrypted controller
credential, the systemd unit, and starts the service. Must run with sudo.

Usage:
    sudo python3 scripts/build_lifecycle_service.py \\
        --identity-id <uuid> --agent-name <slug> \\
        [--database-url sqlite:////var/lib/ucii/database/pq_auth.db]
"""
import argparse
import grp
import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path

SERVICE_TEMPLATE = """[Unit]
Description=UCII {Agent} Protected Controller Lifecycle
After=network.target ucii.service

[Service]
Type=simple
User=ucii-{slug}-lifecycle
Group=ucii-{slug}-lifecycle-ipc
SupplementaryGroups=ucii-database
WorkingDirectory=/
Environment=PYTHONPATH=/opt/ucii/UCII/src
Environment=DATABASE_URL={database_url}
Environment=DEBUG=False
Environment=UCII_CONTROLLER_LIFECYCLE_SOCKET_PATH=/run/ucii-{slug}-lifecycle/lifecycle.sock
Environment=UCII_CONTROLLER_LIFECYCLE_IPC_GROUP=ucii-{slug}-lifecycle-ipc
LoadCredentialEncrypted=controller-authority:/etc/ucii-{slug}-authority/agent-controller-authority.cred
ExecStart=/opt/ucii/UCII/.venv/bin/python -m ucii_agents.controller_lifecycle_service
StateDirectory=ucii-{slug}-lifecycle
StateDirectoryMode=0700
RuntimeDirectory=ucii-{slug}-lifecycle
RuntimeDirectoryMode=0750
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ucii/database
RestrictAddressFamilies=AF_UNIX AF_INET
UMask=0007

[Install]
WantedBy=multi-user.target
"""


def sh(*cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--identity-id", required=True)
    ap.add_argument("--agent-name", required=True,
                    help="short slug, e.g. rocky")
    ap.add_argument("--database-url",
                    default="sqlite:////var/lib/ucii/database/pq_auth.db")
    ap.add_argument("--controller-authority-enc",
                    default="/opt/ucii/ucii-agent-gate/controller_authority.enc")
    args = ap.parse_args()

    slug = args.agent_name
    user = f"ucii-{slug}-lifecycle"
    ipc_group = f"ucii-{slug}-lifecycle-ipc"

    # 1. group + user
    try:
        grp.getgrnam(ipc_group)
    except KeyError:
        sh("groupadd", "-r", ipc_group)
    try:
        pwd.getpwnam(user)
    except KeyError:
        sh("useradd", "-r", "-g", ipc_group, "-G", "ucii-database",
           "-d", "/nonexistent", "-s", "/usr/sbin/nologin",
           "-c", f"UCII {slug} Protected Controller Lifecycle", user)
    print(f"user/group: {user} / {ipc_group}")

    # 2. encrypted credential: decrypt controller authority, repackage,
    #    re-encrypt with host key
    enc_src = Path(args.controller_authority_enc)
    dec = sh("systemd-creds", "decrypt", "--name=controller-authority",
             str(enc_src), "-")
    staged = json.loads(dec.stdout)
    if staged.get("identity_id") != args.identity_id:
        raise SystemExit(
            "controller authority identity mismatch: "
            f"{staged.get('identity_id')} != {args.identity_id}"
        )
    cred_doc = json.dumps({
        "version": "ucii-controller-authority-v1",
        "identity_id": args.identity_id,
        "controller_authority": staged["controller_authority"],
    })
    cred_dir = Path(f"/etc/ucii-{slug}-authority")
    cred_dir.mkdir(parents=True, exist_ok=True)
    cred_file = cred_dir / "agent-controller-authority.cred"
    enc = sh("systemd-creds", "encrypt", "--with-key=host",
             "--name=controller-authority", "-", str(cred_file),
             input=cred_doc)
    if enc.returncode != 0:
        raise SystemExit(f"credential encrypt failed: {enc.stderr[:200]}")
    os.chmod(cred_file, 0o600)
    os.chown(cred_file, 0, 0)
    print(f"credential: {cred_file}")

    # 3. systemd unit
    unit = SERVICE_TEMPLATE.format(
        Agent=slug.capitalize(), slug=slug,
        database_url=args.database_url,
    )
    unit_path = Path(f"/etc/systemd/system/ucii-{slug}-lifecycle.service")
    unit_path.write_text(unit)
    sh("systemctl", "daemon-reload")
    sh("systemctl", "enable", f"ucii-{slug}-lifecycle.service")
    print(f"unit: {unit_path}")

    # 4. start + verify socket
    sh("systemctl", "restart", f"ucii-{slug}-lifecycle.service")
    sock = Path(f"/run/ucii-{slug}-lifecycle/lifecycle.sock")
    for _ in range(20):
        if sock.exists():
            break
        time.sleep(1)
    else:
        raise SystemExit("socket never appeared — check journalctl")
    active = sh("systemctl", "is-active",
                f"ucii-{slug}-lifecycle.service").stdout.strip()
    print(f"service: {active}, socket: {sock}")
    print("OK")


if __name__ == "__main__":
    main()
