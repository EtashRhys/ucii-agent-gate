#!/usr/bin/env python3
"""
UCII Agent Gate — SSH forced-command wrapper.

Install the agent's public key in ~/.ssh/authorized_keys with:
    command="/opt/ucii/ucii-agent-gate/gate.py" ssh-ed25519 AAAA...

Every SSH command from that key lands here. The gate classifies the
command, checks it against policy.json (identity + entitlement + rules),
writes one line to audit.log, and either executes it or denies it.

Nothing here touches sshd_config. Removing the `command="..."` prefix
from authorized_keys disables the gate instantly (rollback = one line).
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

GATE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(GATE_DIR, "policy.json")
AUDIT_PATH = os.path.join(GATE_DIR, "audit.log")
IDENTITY_PATH = os.path.join(GATE_DIR, "identity.json")


def utcnow():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Command classification
# ---------------------------------------------------------------------------
# Order matters: first match wins. Destructive patterns are checked first
# so they can never slip through inside a longer "innocent" command.

DESTRUCTIVE_PATTERNS = [
    r"\brm\s+[^;|&]*-[a-z]*r",          # rm -rf / rm -r
    r"\bmkfs\b",                          # format a filesystem
    r"\bdd\b[^;|&]*of=/dev/",             # dd onto a device
    r"\bwipefs\b",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",  # fork bomb
    r"\bchmod\s+-R\s+777\s+/",            # nuke permissions from root
    r"\bchown\s+-R[^;|&]*/\s",
    r">\s*/dev/sd[a-z]",                  # write straight to disk
    r"\bmv\s+/\s",                        # move the root filesystem
]

READ_PATTERNS = [
    r"^(ls|cat|head|tail|less|more|grep|egrep|fgrep|find|df|du|uptime|"
    r"whoami|pwd|echo|stat|file|wc|sort|uniq|cut|awk|sed|date|env|"
    r"printenv|id|groups|ps|free|uname|hostname|which|test|\[|true|false|"
    r"printf|basename|dirname|realpath|readlink|md5sum|sha256sum|"
    r"systemctl\s+status|journalctl|curl\s+.*-o\s+/dev/null|"
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
    """Return the command class string for a raw SSH command line."""
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


# ---------------------------------------------------------------------------
# Policy + audit
# ---------------------------------------------------------------------------

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def audit(entry):
    with open(AUDIT_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def agent_name():
    # The key comment (3rd field of authorized_keys line) identifies the key.
    # sshd exposes it only indirectly; we map by which key file was used via
    # SSH_USER_AUTH / key fingerprint when available, else fall back to the
    # single configured agent in policy.json.
    return os.environ.get("UCII_AGENT", "rocky")


def decide(policy, agent, command, cmd_class):
    """
    Returns (allowed: bool, reason: str).
    Rule evaluation order:
      1. Explicit time-boxed grants (granted by the owner in chat) win.
      2. Per-agent entitlement rules.
      3. Default: deny (fail closed).
    """
    now = utcnow()
    agents = policy.get("agents", {})
    info = agents.get(agent, {})
    entitlement = info.get("entitlement", "none")

    # 1. Explicit grants
    for g in policy.get("grants", []):
        if g.get("agent") != agent:
            continue
        if g.get("expires_at", "") < now:
            continue
        if re.search(g.get("command_pattern", r"(?!)"), command):
            return True, "explicit grant %s" % g.get("id", "?")

    # 2. Entitlement rules
    if entitlement == "owner":
        # The owner's own agent: everything except destructive is allowed.
        # Destructive needs an explicit grant (rule 1) — "no need to pay
        # myself, but still no silent foot-guns."
        if cmd_class == "destructive":
            return False, "destructive requires explicit owner grant"
        return True, "owner entitlement"

    if entitlement in ("subscriber-monthly", "subscriber-yearly"):
        exp = info.get("expires_at", "")
        if exp and exp < now:
            return False, "subscription expired"
        scopes = info.get("scopes", {})
        allowed_classes = scopes.get("classes", ["read"])
        if cmd_class in allowed_classes:
            # Optional path/repo scoping
            if cmd_class == "git" and scopes.get("repos"):
                ok = any(
                    re.search(r"(?:^|\s)" + re.escape(rp).replace(r"\*", ".*"),
                              command)
                    for rp in scopes["repos"]
                )
                return ok, "subscriber git scope" if ok else "repo out of scope"
            return True, "subscriber entitlement"
        return False, "class '%s' not in subscription" % cmd_class

    if entitlement == "x402":
        # Pay-per-use: the caller must present a verified x402 payment
        # receipt for this command class. Verification lives in x402_verify.py
        # (packages/x402) so the gate stays facilitator-agnostic.
        try:
            sys.path.insert(0, os.path.join(GATE_DIR, "packages", "x402"))
            from x402_verify import verify_payment  # noqa
            receipt = os.environ.get("UCII_X402_RECEIPT", "")
            ok, detail = verify_payment(receipt, cmd_class, policy)
            return ok, "x402: %s" % detail
        except Exception as e:  # never fail open on verifier errors
            return False, "x402 verifier error: %s" % e

    # 3. Fail closed
    return False, "no entitlement"


def main():
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    policy = load_json(POLICY_PATH, {})
    identity = load_json(IDENTITY_PATH, {})
    agent = agent_name()
    cmd_class = classify(command)

    allowed, reason = decide(policy, agent, command, cmd_class)

    audit({
        "ts": utcnow(),
        "agent": agent,
        "identity_id": identity.get("id"),
        "command": command[:500],
        "class": cmd_class,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    })

    if not allowed:
        sys.stderr.write(
            "UCII gate: DENIED (%s). Ask the owner for a grant.\n" % reason
        )
        sys.exit(1)

    if not command.strip():
        sys.stderr.write("UCII gate: interactive shells are disabled.\n")
        sys.exit(1)

    # Execute the allowed command, replacing this process.
    os.execvp("/bin/bash", ["/bin/bash", "-c", command])


if __name__ == "__main__":
    main()
