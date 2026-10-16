#!/usr/bin/env python3
"""
UCII Agent Gate v2 — SSH forced-command wrapper, UCII-authority edition.

Install the agent's public key in ~/.ssh/authorized_keys with:
    command="/opt/ucii/ucii-agent-gate/gate.py" ssh-ed25519 AAAA...

Every SSH command from that key lands here. The gate:

  1. Classifies the command (read/git/file-op/service/destructive).
  2. Asks Brad's UCII server — POST /v1/authorization/delegated/check —
     signed with the agent's UCII credential (ML-DSA-65). The SERVER
     decides; the gate enforces. This endpoint is free (not x402-metered).
  3. Falls back to local policy.json ONLY for the owner entitlement,
     and logs the fallback. (Fail-closed for everyone else.)
  4. Writes one line per decision to audit.log.

Setup (one time, needs Brad's controller authority):
  a. Generate a keypair:  python3 scripts/ucii_setup.py --gen-key
  b. Brad registers the AI_AGENT identity + credential on the UCII server
     and grants delegated authority for ssh.exec:* operations.
  c. Save the credential to ucii_credential.json (mode 600).
  Until then, the gate runs on local policy.json and says so in the audit log.

Rollback: delete the `command="..."` prefix from authorized_keys. One line.
"""

import base64
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

GATE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(GATE_DIR, "policy.json")
CREDENTIAL_PATH = os.path.join(GATE_DIR, "ucii_credential.json")
AUDIT_PATH = os.path.join(GATE_DIR, "audit.log")
IDENTITY_PATH = os.path.join(GATE_DIR, "identity.json")

UCII_SERVER = os.environ.get("UCII_SERVER", "http://127.0.0.1:8000")
# oqs (ML-DSA-65) lives in the UCII venv; make it importable.
_VENV_SP = "/opt/ucii/UCII/.venv/lib/python3.12/site-packages"
if os.path.isdir(_VENV_SP) and _VENV_SP not in sys.path:
    sys.path.insert(0, _VENV_SP)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Command classification (unchanged from v1)
# ---------------------------------------------------------------------------

DESTRUCTIVE_PATTERNS = [
    r"\brm\s+[^;|&]*-[a-z]*r",
    r"\bmkfs\b",
    r"\bdd\b[^;|&]*of=/dev/",
    r"\bwipefs\b",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",
    r"\bchmod\s+-R\s+777\s+/",
    r"\bchown\s+-R[^;|&]*/\s",
    r">\s*/dev/sd[a-z]",
    r"\bmv\s+/\s",
]

READ_PATTERNS = [
    r"^(ls|cat|head|tail|less|more|grep|egrep|fgrep|find|df|du|uptime|"
    r"whoami|pwd|echo|stat|file|wc|sort|uniq|cut|awk|sed|date|env|"
    r"printenv|id|groups|ps|free|uname|hostname|which|test|\[|true|false|"
    r"printf|basename|dirname|realpath|readlink|md5sum|sha256sum|"
    r"systemctl\s+status|journalctl|"
    r"git\s+(status|log|diff|show|branch|remote|fetch))\b",
]

GIT_PATTERNS = [
    r"^\s*git\s+(clone|pull|push|fetch|commit|add|checkout|merge|rebase|tag)\b",
]

FILE_OP_PATTERNS = [
    r"^\s*(mkdir|touch|cp|mv|ln|chmod|chown|tee|unzip|tar|rsync|scp)\b",
]

SERVICE_PATTERNS = [
    r"^\s*(python3?|pip3?|node|npm|cargo|go|java|dotnet)\b",
    r"^\s*systemctl\s+(start|stop|restart|reload|enable|disable)\b",
    r"^\s*(nginx|certbot)\b",
    r"^\s*crontab\b",
]


def classify(command):
    if not command or not command.strip():
        return "empty"
    for pat in DESTRUCTIVE_PATTERNS:
        if re.search(pat, command):
            return "destructive"
    for pat in READ_PATTERNS:
        if re.search(pat, command):
            return "read"
    for pat in GIT_PATTERNS:
        if re.search(pat, command):
            return "git"
    for pat in FILE_OP_PATTERNS:
        if re.search(pat, command):
            return "file-op"
    for pat in SERVICE_PATTERNS:
        if re.search(pat, command):
            return "service"
    if command.strip().startswith("scp "):
        return "file-op"
    return "unclassified"


# Command class -> UCII operation string (what Brad grants).
CLASS_TO_OPERATION = {
    "read": "ssh.exec:read",
    "git": "ssh.exec:git",
    "file-op": "ssh.exec:file-op",
    "service": "ssh.exec:service",
    "destructive": "ssh.exec:destructive",
    "unclassified": "ssh.exec:unclassified",
    "empty": "ssh.exec:empty",
}


# ---------------------------------------------------------------------------
# UCII authority check (primary)
# ---------------------------------------------------------------------------

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def ucii_check(command, cmd_class):
    """
    Ask the UCII server. Returns (allowed, reason) or None when the
    gate has no UCII credential yet / the server is unreachable.
    """
    cred = load_json(CREDENTIAL_PATH, {})
    identity_id = cred.get("identity_id")
    fingerprint = cred.get("credential_fingerprint")
    secret_b64 = cred.get("private_key_b64")
    if not (identity_id and fingerprint and secret_b64):
        return None  # not wired up yet

    try:
        import oqs
    except ImportError:
        return None  # oqs missing; fall back

    operation = CLASS_TO_OPERATION.get(cmd_class, "ssh.exec:unclassified")
    # Fresh signed message: operation + timestamp + command hash, so every
    # check is bound to this exact moment and command (replay-resistant).
    import hashlib
    message = "|".join([
        "ucii-gate-check-v1",
        identity_id,
        operation,
        utcnow(),
        hashlib.sha256(command.encode()).hexdigest()[:16],
    ])
    try:
        sig = oqs.Signature("ML-DSA-65", base64.b64decode(secret_b64))
        signature = base64.b64encode(sig.sign(message.encode())).decode()
    except Exception as e:
        return None  # signing failed; fall back, don't fail open blindly

    payload = {
        "identity_id": identity_id,
        "credential_fingerprint": fingerprint,
        "operation": operation,
        "message": message,
        "signature": signature,
    }
    try:
        req = urllib.request.Request(
            UCII_SERVER.rstrip("/") + "/v1/authorization/delegated/check",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
    except Exception:
        return None  # server unreachable; fall back

    if result.get("authorized"):
        return True, "UCII delegated authority (%s)" % result.get(
            "authority_id", "grant")
    return False, "UCII denied: %s" % result.get(
        "authority_state", "not authorized")


# ---------------------------------------------------------------------------
# Local policy fallback (owner only, v1 behavior)
# ---------------------------------------------------------------------------

def local_decide(policy, agent, command, cmd_class):
    now = utcnow()
    agents = policy.get("agents", {})
    info = agents.get(agent, {})
    entitlement = info.get("entitlement", "none")

    for g in policy.get("grants", []):
        if g.get("agent") != agent:
            continue
        if g.get("expires_at", "") < now:
            continue
        if re.search(g.get("command_pattern", r"(?!)"), command):
            return True, "explicit grant %s (local fallback)" % g.get("id", "?")

    if entitlement == "owner":
        if cmd_class == "destructive":
            return False, ("destructive requires explicit owner grant "
                           "(local fallback)")
        return True, "owner entitlement (local fallback)"

    return False, "no UCII credential and no local entitlement"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def audit(entry):
    with open(AUDIT_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def agent_name():
    return os.environ.get("UCII_AGENT", "rocky")


def main():
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    agent = agent_name()
    cmd_class = classify(command)
    identity = load_json(IDENTITY_PATH, {})

    # Primary: UCII server. Fallback: local policy (owner only).
    result = ucii_check(command, cmd_class)
    if result is None:
        policy = load_json(POLICY_PATH, {})
        allowed, reason = local_decide(policy, agent, command, cmd_class)
        via = "local-policy"
    else:
        allowed, reason = result
        via = "ucii-server"

    audit({
        "ts": utcnow(),
        "agent": agent,
        "identity_id": identity.get("id"),
        "command": command[:500],
        "class": cmd_class,
        "via": via,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    })

    if not allowed:
        sys.stderr.write("UCII gate: DENIED (%s).\n" % reason)
        sys.exit(1)

    if not command.strip():
        sys.stderr.write("UCII gate: interactive shells are disabled.\n")
        sys.exit(1)

    os.execvp("/bin/bash", ["/bin/bash", "-c", command])


if __name__ == "__main__":
    main()
