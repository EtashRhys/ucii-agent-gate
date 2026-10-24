#!/usr/bin/env python3
"""
UCII Agent Gate v2 — SSH forced-command wrapper, UCII-authority edition.

Install the agent's public key in ~/.ssh/authorized_keys with:
    command="/opt/ucii/ucii-agent-gate/gate.py" ssh-ed25519 AAAA...

Every SSH command from that key lands here. The gate:

  1. Classifies the command (read/git/file-op/service/destructive).
  2. Asks the UCII Admin server — POST /v1/authorization/delegated/check —
     signed with the agent's UCII credential (ML-DSA-65). The SERVER
     decides; the gate enforces. This endpoint is free (not x402-metered).
  3. Falls back to local policy.json ONLY for the owner entitlement,
     and logs the fallback. (Fail-closed for everyone else.)
  4. Writes one line per decision to audit.log.

  DESTRUCTIVE NEVER GOES THROUGH THE GATE. A destructive-classified
  command is denied at the gate itself, before any grant is consulted.
  Destructive work happens at the operator's own terminal, not the
  agent's. (Decision: Brad, 2026-10-23.)

Setup (one time, needs the UCII Admin's controller authority):
  a. Generate a keypair:  python3 scripts/ucii_setup.py --gen-key
  b. The UCII Admin registers the AI_AGENT identity + credential on the UCII server
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
CHECK_SIGNING_KEY_PATH = os.path.join(
    GATE_DIR, "check_signing_key.json"
)
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
    r"\brm\s+[^;|&]*-[a-zA-Z]*[rR]",
    r"\brm\s+[^;|&]*--recursive",
    r"^\s*rm\b",
    r"^\s*shred\b",
    r"^\s*truncate\b",
    r"^\s*dd\b[^;|&]*\bof=",
    r"\bmkfs\b",
    r"\bdd\b[^;|&]*of=/dev/",
    r"\bwipefs\b",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",
    r"\bchmod\s+-R\s+777\s+/",
    r"\bchown\s+-R[^;|&]*/(\s|$)",
    r">\s*/dev/sd[a-z]",
    r"\bmv\s+/\s",
]

READ_PATTERNS = [
    r"^(ls|cat|head|tail|less|more|grep|egrep|fgrep|find|df|du|uptime|"
    r"whoami|pwd|echo|stat|file|wc|sort|uniq|cut|awk|sed|date|env|diff|cmp|comm|"
    r"printenv|id|groups|ps|free|uname|hostname|which|test|\[|true|false|"
    r"printf|basename|dirname|realpath|readlink|md5sum|sha256sum|"
    r"systemctl\s+status|journalctl)\b",
    r"^\s*cd\b",
    r"^\s*git\s+(--version|--help)\b",
    r"^\s*git\s*$",
    r"^\s*systemctl\s+(is-active|is-enabled|is-failed|show|"
    r"list-units|list-sockets|list-timers|cat)\b",
]

# git is priced by _classify_git (subcommand + argument rules).

FILE_OP_PATTERNS = [
    r"^\s*(mkdir|touch|cp|mv|ln|chmod|chown|tee|unzip|tar|rsync|scp)\b",
    # Modern scp(1) runs the SFTP subsystem: SSH_ORIGINAL_COMMAND is the
    # sftp-server binary, not "scp -t". Treat it as a file transfer.
    r"sftp-server",
]

SERVICE_PATTERNS = [
    r"^\s*(python3?|pip3?|node|npm|cargo|go|java|dotnet)\b",
    r"^\s*systemctl\s+(start|stop|restart|reload|enable|disable)\b",
    r"^\s*(nginx|certbot)\b",
]


# Severity order: highest risk first (for combining compound parts).
CLASS_SEVERITY = [
    "destructive", "unclassified", "service", "file-op", "git",
    "read", "empty",
]


def split_compound(command):
    """Split on && || ; | newline and bare &, respecting quotes.

    A bare & is a command separator in bash (background operator). It is
    not a separator inside `&>` (redirect-all), `>&` (fd duplication), or
    `2>&1`-style fd juggling, where the previous character is `>`.
    """
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
            elif c in (";", "|", "\n"):
                parts.append("".join(current).strip())
                current = []
            elif c == "&":
                prev = current[-1] if current else ""
                nxt = command[i + 1] if i + 1 < n else ""
                if prev == ">" or nxt == ">":
                    current.append(c)  # redirect syntax, not a separator
                else:
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
    """True if the part redirects output to a file (a write).

    Any `>` that is not fd duplication (`>&1`, `>&-`) writes to a file —
    including `2>file` and `&>file`. An earlier version stripped those
    before checking; stderr redirection still creates the file.
    Redirects to /dev/null are discards, not writes, and are exempt
    (audit-log replay, 2026-10-23: 53 real read commands carried
    `2>/dev/null`; pricing them as writes distorted the audit trail
    and would overcharge x402 reads).
    """
    part = re.sub(r"&>>?\s*/dev/null", "", part)
    part = re.sub(r"\d*>>?\s*/dev/null", "", part)
    i, n = 0, len(part)
    while i < n:
        if part[i] == ">":
            nxt = part[i + 1] if i + 1 < n else ""
            if nxt == "&":
                after = part[i + 2] if i + 2 < n else ""
                if after.isdigit() or after == "-":
                    i += 2
                    continue
                return True
            return True
        if part[i] == "&" and i + 1 < n and part[i + 1] == ">":
            return True
        i += 1
    return False


def _substitution_inners(part):
    """Inner strings of $(...), `...`, <(...) outside single quotes.

    Substitution executes even inside double quotes, so only
    single-quoted spans are literal. Returns (inners, unbalanced).
    """
    inners, i, n = [], 0, len(part)
    in_single = False
    while i < n:
        c = part[i]
        if c == "'":
            in_single = not in_single
            i += 1
            continue
        if in_single:
            i += 1
            continue
        if part.startswith("$(", i) or part.startswith("<(", i):
            depth, j = 0, i + 1
            start = j + 1
            while j < n:
                if part[j] == "(":
                    depth += 1
                elif part[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth != 0:
                return inners, True
            inners.append(part[start:j])
            i = j + 1
            continue
        if c == "`":
            j = part.find("`", i + 1)
            if j == -1:
                return inners, True
            inners.append(part[i + 1:j])
            i = j + 1
            continue
        i += 1
    return inners, False


def _tokens(part):
    import shlex
    p = part.strip()
    if p.endswith("\\") and not p.endswith("\\\\"):
        p = p[:-1]  # trailing escape left by compound splitting (\;)
    try:
        return shlex.split(p)
    except ValueError:
        return None


def _strictest(classes):
    for c in CLASS_SEVERITY:
        if c in classes:
            return c
    return "unclassified"


def _normalized(part):
    """Reduce a path-prefixed verb (/usr/bin/sed) to its basename so the
    pattern lists and verb rules see one form. Arguments are untouched."""
    m = re.match(r"^\s*(\S+)(.*)$", part, re.DOTALL)
    if m and "/" in m.group(1):
        return os.path.basename(m.group(1)) + m.group(2)
    return part


def _classify_git(tokens):
    """Price a git command by subcommand and arguments.

    Read-only git: status; log/show/diff without --output; branch and
    remote in their list forms; bare invocations. Ref/config/worktree
    writes are git-class; clean and reset --hard destroy work and are
    destructive. Global flags (-C, -c, ...) fail closed.
    """
    if len(tokens) < 2:
        return "read"
    sub = tokens[1]
    if sub in ("--version", "--help"):
        return "read"
    if sub.startswith("-"):
        return "unclassified"
    args = tokens[2:]
    if sub == "status":
        return "read"
    if sub in ("log", "show", "diff"):
        if any(a.startswith("--output") for a in args):
            return "file-op"
        return "read"
    if sub == "branch":
        if not args:
            return "read"
        write_flags = {"-d", "-D", "-m", "-M", "-c", "-C", "-u", "-f",
                       "--delete", "--move", "--copy", "--force",
                       "--unset-upstream"}
        if any(a in write_flags or a.startswith("--set-upstream")
               for a in args):
            return "git"
        list_flags = {"-a", "-r", "-v", "-vv", "--all", "--list",
                      "--verbose", "--show-current"}
        if all(a in list_flags or a.startswith("--format")
               for a in args):
            return "read"
        return "git"  # a positional name creates a branch
    if sub == "remote":
        if not args or args[0] in ("-v", "--verbose", "show", "get-url"):
            return "read"
        return "git"
    if sub in ("fetch", "pull", "push", "clone", "commit", "add",
               "checkout", "merge", "rebase", "tag"):
        return "git"
    if sub == "clean":
        return "destructive"
    if sub == "reset":
        return "destructive" if "--hard" in args else "unclassified"
    return "unclassified"


def _classify_find(tokens, depth):
    """find is a read only without its payload flags."""
    for i, t in enumerate(tokens):
        if t == "-delete":
            return "destructive"
        if t in ("-exec", "-execdir"):
            payload = []
            for u in tokens[i + 1:]:
                if u in (";", "+"):
                    break
                payload.append(u)
            if payload:
                return _classify(" ".join(payload), depth + 1)
            return "service"
        if t in ("-fprint", "-fprintf", "-fls"):
            return "file-op"
    return "read"


def _classify_sed(tokens):
    """sed edits in place with -i, writes with the s///w and w commands,
    and executes with the e command. A script FILE (-f) cannot be
    inspected, so it is priced as a write. Returns None for plain
    to-stdout sed (priced by the read patterns)."""
    args = tokens[1:]
    for a in args:
        if a == "--in-place" or a.startswith("--in-place="):
            return "file-op"
        if a.startswith("-") and not a.startswith("--") and "i" in a[1:]:
            return "file-op"
        if a in ("-f", "--file"):
            return "file-op"
    script = " ".join(args)
    if re.search(r"(^|[;\s])e\s+\S", script) or re.search(r"\de\s+\S", script):
        return "service"
    if re.search(r"/w\s+\S", script) or re.search(r"(^|[;\s])w\s+\S", script):
        return "file-op"
    return None


def _classify_awk(tokens):
    """awk executes via system() and the getline pipe. (awk's print >
    is already caught by the redirect check.)"""
    prog = " ".join(tokens[1:])
    if "system(" in prog or "getline" in prog:
        return "service"
    return None


def _classify_sort(tokens):
    if any(a == "-o" or a.startswith("--output") for a in tokens[1:]):
        return "file-op"
    return None


def _classify_uniq(tokens):
    skip_next = {"-f", "-s", "-w"}
    operands, i = [], 1
    while i < len(tokens):
        t = tokens[i]
        if t in skip_next:
            i += 2
            continue
        if not t.startswith("-"):
            operands.append(t)
        i += 1
    if len(operands) >= 2:
        return "file-op"
    return None


def _classify_journalctl(tokens):
    bad = ("--vacuum", "--rotate", "--flush", "--sync", "--relinquish",
           "--smart-relinquish")
    if any(a.startswith(bad) for a in tokens[1:]):
        return "file-op"
    return None


def _classify_date(tokens):
    if any(a in ("-s", "--set") or a.startswith("--set=")
           for a in tokens[1:]):
        return "service"
    return None


def _classify_crontab(tokens):
    if tokens[1:] == ["-l"]:
        return "read"
    return "service"


def _classify_wrapper(tokens, depth):
    """env / nohup / time / sudo / xargs are launchers: the payload
    decides the class, not the wrapper. Returns None if the verb is
    not a wrapper."""
    verb = os.path.basename(tokens[0])
    rest = tokens[1:]
    if verb == "env":
        i = 0
        while i < len(rest):
            t = rest[i]
            if t in ("-i", "--ignore-environment", "-0", "--null",
                     "--debug"):
                i += 1
            elif t in ("-u", "--unset", "-S", "--split-string"):
                i += 2
            elif t == "--":
                i += 1
                break
            elif "=" in t and not t.startswith("-"):
                i += 1  # VAR=value assignment
            else:
                break
        payload = rest[i:]
        if not payload:
            return "read"  # bare env prints the environment
        return _classify(" ".join(payload), depth + 1)
    if verb in ("nohup", "time"):
        if not rest:
            return "unclassified"
        return _classify(" ".join(rest), depth + 1)
    if verb == "sudo":
        if not rest:
            return "unclassified"
        inner = _classify(" ".join(rest), depth + 1)
        return _strictest([inner, "service"])
    if verb == "xargs":
        i = 0
        while i < len(rest):
            t = rest[i]
            if t in ("-I", "-L", "-n", "-P", "-s", "-E", "-e", "-d",
                     "-a"):
                i += 2
            elif t.startswith("-"):
                i += 1
            else:
                break
        payload = rest[i:]
        if not payload:
            return "unclassified"
        return _classify(" ".join(payload), depth + 1)
    return None


def _classify_direct(part, depth):
    """Price one simple command with no substitution (handled by the
    caller), after basename normalization."""
    part = _normalized(part)
    for pat in DESTRUCTIVE_PATTERNS:
        if re.search(pat, part):
            return "destructive"
    if has_output_redirect(part):
        return "file-op"
    tokens = _tokens(part)
    if tokens:
        verb = os.path.basename(tokens[0])
        if verb == "git":
            return _classify_git(tokens)
        wrapped = _classify_wrapper(tokens, depth)
        if wrapped is not None:
            return wrapped
        rule = None
        if verb == "find":
            rule = _classify_find(tokens, depth)
        elif verb == "sed":
            rule = _classify_sed(tokens)
        elif verb == "awk":
            rule = _classify_awk(tokens)
        elif verb == "sort":
            rule = _classify_sort(tokens)
        elif verb == "uniq":
            rule = _classify_uniq(tokens)
        elif verb == "journalctl":
            rule = _classify_journalctl(tokens)
        elif verb == "date":
            rule = _classify_date(tokens)
        elif verb == "crontab":
            rule = _classify_crontab(tokens)
        if rule is not None:
            return rule
    for pat in READ_PATTERNS:
        if re.search(pat, part):
            return "read"
    for pat in FILE_OP_PATTERNS:
        if re.search(pat, part):
            return "file-op"
    for pat in SERVICE_PATTERNS:
        if re.search(pat, part):
            return "service"
    if part.strip().startswith("scp "):
        return "file-op"
    return "unclassified"


def _classify_single(part, depth):
    if depth > 4:
        return "unclassified"
    inners, unbalanced = _substitution_inners(part)
    if unbalanced:
        return "unclassified"
    classes = [_classify_direct(part, depth)]
    classes += [_classify(s, depth + 1) for s in inners]
    return _strictest(classes)


def classify_single(part):
    """Classify one shell-simple command (no compounds)."""
    return _classify_single(part, 0)


def _classify(command, depth):
    if not command or not command.strip():
        return "empty"
    classes = [_classify_single(p, depth) for p in split_compound(command)]
    return _strictest(classes) if classes else "empty"


def classify(command):
    """Classify a full command; compounds take the strictest part class."""
    return _classify(command, 0)


def classify_parts(command):
    """Return [(part, class)] for compound commands (for per-part checks)."""
    parts = split_compound(command)
    if not parts:
        return [("", "empty")]
    return [(p, classify_single(p)) for p in parts]


# Command class -> UCII operation string (what the UCII Admin grants).
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


def verify_check_response(result, request_message):
    """Verify the server's signature on a check response (fix #1).

    Returns None when the response is authentic, bound to this exact
    request, and unexpired; otherwise a denial reason. A verification
    failure is a HARD denial - the caller must not fall back to local
    policy for it (that fallback exists for an unreachable server,
    not for an untrustworthy answer).
    """
    import hashlib
    import io
    try:
        key_cfg = load_json(CHECK_SIGNING_KEY_PATH, {})
        key_id = key_cfg.get("key_id")
        pub_b64 = key_cfg.get("public_key_b64")
        if not key_id or not pub_b64:
            return "UCII response unverifiable: no pinned signing key"
        if result.get("server_key_id") != key_id:
            return "UCII response denied: signing key id mismatch"
        signature = result.get("server_signature")
        server_ts = result.get("server_ts")
        expires_at = result.get("expires_at")
        if not signature or not server_ts or not expires_at:
            return "UCII response denied: unsigned check response"
        canonical = "|".join([
            "ucii-check-response-v1",
            key_id,
            result.get("identity_id", ""),
            result.get("operation", ""),
            "true" if result.get("authorized") else "false",
            "true" if result.get("executed") else "false",
            result.get("credential_fingerprint", ""),
            result.get("credential_status", ""),
            result.get("authority_state", ""),
            result.get("authority_id") or "",
            hashlib.sha256(request_message.encode()).hexdigest(),
            server_ts,
            expires_at,
        ])
        try:
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                import oqs
            verifier = oqs.Signature("ML-DSA-65")
            ok = verifier.verify(
                canonical.encode(),
                base64.b64decode(signature),
                base64.b64decode(pub_b64),
            )
        except Exception:
            return "UCII response denied: signature verification error"
        if not ok:
            return "UCII response denied: signature invalid"
        exp = datetime.fromisoformat(expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            return "UCII response denied: signed response expired"
        return None
    except Exception:
        return "UCII response denied: verification failure"


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
        # oqs prints to stdout on import ("faulthandler is disabled"),
        # which breaks scp/sftp protocol. Silence it.
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            import oqs
    except ImportError:
        return None  # oqs missing; fall back

    operation = CLASS_TO_OPERATION.get(cmd_class, "ssh.exec:unclassified")
    # Fresh signed message: operation + timestamp + command hash, so every
    # check is bound to this exact moment and command (replay-resistant).
    import hashlib
    message = "|".join([
        "ucii-gate-check-v2",
        identity_id,
        operation,
        utcnow(),
        hashlib.sha256(command.encode()).hexdigest(),
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

    problem = verify_check_response(result, message)
    if problem is not None:
        return False, problem

    if result.get("authorized"):
        return True, "UCII delegated authority (%s)" % result.get(
            "authority_id", "grant")
    return False, "UCII denied: %s" % result.get(
        "authority_state", "not authorized")


# ---------------------------------------------------------------------------
# Local policy fallback (owner only, v1 behavior)
# ---------------------------------------------------------------------------

def local_decide_parts(policy, agent, parts):
    """Local fallback, judged per part.

    A grant authorizes only the part its pattern matches — never the
    whole compound string (attack battery 8-01: a `cat` grant priced a
    `chmod` riding in the same command when the pattern was searched
    against the full string). The owner entitlement covers every part
    except destructive, which decide() denies before this is consulted.
    """
    now = utcnow()
    agents = policy.get("agents", {})
    info = agents.get(agent, {})
    entitlement = info.get("entitlement", "none")
    grants = [g for g in policy.get("grants", [])
              if g.get("agent") == agent
              and g.get("expires_at", "") >= now]
    for part, cls in parts:
        if cls == "destructive":
            return False, "destructive never goes through the gate"
        if any(re.search(g.get("command_pattern", r"(?!)"), part)
               for g in grants):
            continue
        if entitlement == "owner":
            continue
        return False, ("no grant matches part %r (%s) and no local "
                       "entitlement" % (part[:60], cls))
    return True, "local fallback (per-part)"


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

    Destructive is denied here, at the gate, before the server or any
    grant is consulted — it never goes through the gate. If the server
    cannot be consulted at all, local policy judges every part
    (all-or-nothing fallback).
    """
    parts = classify_parts(command)
    cmd_class = classify(command)
    if cmd_class == "destructive":
        return (False, "destructive never goes through the gate",
                "gate", cmd_class)
    if cmd_class == "empty":
        return False, "empty command", "gate", cmd_class

    distinct = []
    for _, c in parts:
        if c not in distinct and c not in ("empty",):
            distinct.append(c)

    reasons = []
    for cls in distinct:
        result = ucii_check(command, cls)
        if result is None:
            policy = load_json(POLICY_PATH, {})
            allowed, reason = local_decide_parts(policy, agent, parts)
            return allowed, reason, "local-policy", cmd_class
        allowed, reason = result
        if not allowed:
            return False, reason, "ucii-server", cmd_class
        reasons.append("%s: %s" % (cls, reason))
    return True, "; ".join(reasons), "ucii-server", cmd_class


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
