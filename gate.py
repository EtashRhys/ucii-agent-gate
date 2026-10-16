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
    r"^\s*cd\b",
    r"^\s*git\s+(--version|--help)\b",
    r"^\s*git\s*$",
    r"^\s*systemctl\s+(is-active|is-enabled|is-failed|show|"
    r"list-units|list-sockets|list-timers|cat)\b",
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


# Severity order: highest risk first (for combining compound parts).
CLASS_SEVERITY = [
    "destructive", "unclassified", "service", "file-op", "git",
    "read", "empty",
]


def split_compound(command):
    """Split on && || ; | respecting single/double quotes."""
    parts, current = [], []
    in_single, in_double = False, False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
        elif not in_single and not in_double:
            two = command[i:i + 2]
            if two in ("&&", "||"):
                parts.append("".join(current).strip())
                current = []
                i += 2
                continue
            elif c in (";", "|"):
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(c)
        else:
            current.append(c)
        i += 1
    parts.append("".join(current).strip())
    return [p for p in parts if p]


def has_output_redirect(part):
    """True if the part redirects stdout to a file (a write)."""
    cleaned = re.sub(r"2\s*>", "", part)
    cleaned = re.sub(r"&\s*>", "", cleaned)
    return bool(re.search(r">", cleaned))


def classify_single(part):
    """Classify one shell-simple command (no compounds)."""
    for pat in DESTRUCTIVE_PATTERNS:
        if re.search(pat, part):
            return "destructive"
    # Output redirect to a file is a write, even on read verbs (echo > f).
    if has_output_redirect(part):
        return "file-op"
    for pat in READ_PATTERNS:
        if re.search(pat, part):
            return "read"
    for pat in GIT_PATTERNS:
        if re.search(pat, part):
            return "git"
    for pat in FILE_OP_PATTERNS:
        if re.search(pat, part):
            return "file-op"
    for pat in SERVICE_PATTERNS:
        if re.search(pat, part):
            return "service"
    if part.strip().startswith("scp "):
        return "file-op"
    return "unclassified"


def classify(command):
    """Classify a full command; compounds take the strictest part class."""
    if not command or not command.strip():
        return "empty"
    classes = [classify_single(p) for p in split_compound(command)]
    for c in CLASS_SEVERITY:
        if c in classes:
            return c
    return "unclassified"


def classify_parts(command):
    """Return [(part, class)] for compound commands (for per-part checks)."""
    parts = split_compound(command)
    if not parts:
        return [("", "empty")]
    return [(p, classify_single(p)) for p in parts]


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


def decide(command, agent):
    """Authorize a (possibly compound) command.

    Every part of a compound command must be authorized. Returns
    (allowed, reason, via, cmd_class) where cmd_class is the strictest
    part class for the audit log.
    """
    parts = classify_parts(command)
    cmd_class = classify(command)
    if cmd_class == "destructive":
        return (False, "destructive requires explicit owner grant",
                "gate", cmd_class)
    if cmd_class == "empty":
        return False, "empty command", "gate", cmd_class

    distinct = []
    for _, c in parts:
        if c not in distinct and c not in ("empty",):
            distinct.append(c)

    via, reasons = "ucii-server", []
    for cls in distinct:
        result = ucii_check(command, cls)
        if result is None:
            policy = load_json(POLICY_PATH, {})
            allowed, reason = local_decide(policy, agent, command, cls)
            via = "local-policy"
        else:
            allowed, reason = result
        if not allowed:
            return False, reason, via, cmd_class
        reasons.append("%s: %s" % (cls, reason))
    return True, "; ".join(reasons), via, cmd_class


def main():
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    agent = agent_name()
    identity = load_json(IDENTITY_PATH, {})

    # Primary: UCII server. Fallback: local policy (owner only).
    allowed, reason, via, cmd_class = decide(command, agent)

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
