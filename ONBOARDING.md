# Wrapping an AI Agent into the UCII Family

This guide walks you through giving an AI agent a real UCII identity —
the same process Rocky (a Muse agent) went through on 2026-10-15.
When you're done, the agent has:

- A registered **AI_AGENT identity** on your UCII server
- Its own **ML-DSA-65 credential** (post-quantum signing key)
- An **ACTIVE delegated authority grant** (what it's allowed to do)
- Its own **protected lifecycle service** (the only thing that can
  grant/revoke authority for that agent)
- A **service entitlement** (so its authority checks aren't metered)

## Plain-language overview

Your UCII server doesn't trust anyone by default — not even your own
AI. "Wrapping" is how you introduce an agent to the server and say
exactly what it's allowed to do. The server then enforces that for
every SSH command the agent tries to run.

Think of it like getting an employee badge: HR creates the identity,
security issues the badge (credential), the manager approves access
levels (grant), and there's a dedicated security desk for that employee
(lifecycle service).

## Prerequisites

- A running UCII server (`ucii.service` on 127.0.0.1:8000)
- The UCII Python venv with `oqs` (ML-DSA-65) installed
- Root/sudo on the server (you're the operator)
- `systemd-creds` available (standard on systemd systems)

## Step 1 — Generate the agent's keypair

The agent needs an ML-DSA-65 signing key. Generate it:

```bash
/opt/ucii/UCII/.venv/bin/python -c "
import base64, hashlib, json, sys
sys.path.insert(0, '/opt/ucii/UCII/.venv/lib/python3.12/site-packages')
import oqs
with oqs.Signature('ML-DSA-65') as sig:
    pub = sig.generate_keypair()
    sec = sig.export_secret_key()
open('agent_public_key.b64', 'w').write(base64.b64encode(pub).decode())
cred = {
    'identity_id': '',
    'credential_fingerprint': hashlib.sha256(pub).hexdigest(),
    'private_key_b64': base64.b64encode(sec).decode(),
    'algorithm': 'ML-DSA-65',
}
json.dump(cred, open('ucii_credential.json', 'w'), indent=2)
import os; os.chmod('ucii_credential.json', 0o600)
print('fingerprint:', cred['credential_fingerprint'])
"
```

**Gotcha:** the private key file must be mode 600. The fingerprint
must be the **full 64-char** SHA-256 hex of the public key — truncated
versions are rejected.

**Gotcha:** in this oqs version, the secret key goes in the
constructor: `oqs.Signature("ML-DSA-65", secret_key_bytes)`. There is
no `import_secret_key` method.

## Step 2 — Provision the identity (operator approval required)

This is the step where **you, the operator**, create the agent's
identity. It uses your server's first-party operator provisioning —
the same flow your other agents went through. It creates the identity,
registers the credential, sets up the service entitlement, and issues
your controller authority (encrypted) — all atomically.

```bash
# One-time: initialize the systemd host key (your provisioning needs it)
sudo systemd-creds setup

# Provision (DATABASE_URL must point at your PRODUCTION database)
sudo DATABASE_URL="sqlite:////var/lib/ucii/database/pq_auth.db" \
  /opt/ucii/UCII/.venv/bin/python scripts/provision_agent.py \
  --name "Agent Name" \
  --description "What this agent does" \
  --public-key agent_public_key.b64
```

**Gotcha:** `DATABASE_URL` **must** point at your production database
(`/var/lib/ucii/database/pq_auth.db`). There may be other `.db` files
on the server (e.g. `/opt/ucii/UCII/pq_auth.db`) — provisioning to the
wrong one creates an identity your API can't see. Verify with:
`curl http://127.0.0.1:8000/v1/identity/<id>`.

**Gotcha:** provisioning must run with sudo — the systemd host key
used to encrypt your controller authority is root-only.

Save the returned `identity_id` into the agent's `ucii_credential.json`.

## Step 3 — Build the agent's lifecycle service

Each agent gets its own protected lifecycle service. This is the
**only** component that can grant or revoke authority for that agent.
(Alexa has one, Voice has one — now your agent gets one.)

```bash
sudo scripts/build_lifecycle_service.py --identity-id <id> --agent-name <name>
```

This creates:
- System user `ucii-<name>-lifecycle` + group `ucii-<name>-lifecycle-ipc`
- Encrypted credential at `/etc/ucii-<name>-authority/agent-controller-authority.cred`
  (systemd-encrypted with the host key — only decryptable on this server)
- Systemd unit `ucii-<name>-lifecycle.service`, enabled on boot
- Starts the service and verifies its socket at `/run/ucii-<name>-lifecycle/lifecycle.sock`

**Gotcha:** the `LoadCredentialEncrypted` name must be
`controller-authority` (the service's default). A custom name will
fail silently — the service starts, then exits with "protected
controller authority could not be established."

## Step 4 — Grant delegated authority (operator approval required)

**You** decide what the agent may do. The grant is issued through the
agent's lifecycle service:

```bash
sudo /opt/ucii/UCII/.venv/bin/python scripts/grant_authority.py \
  --socket /run/ucii-<name>-lifecycle/lifecycle.sock \
  --operations ssh.exec:read ssh.exec:git ssh.exec:file-op ssh.exec:service \
  --granted-by <your-handle>
```

Operation classes:
- `ssh.exec:read` — read-only commands (uptime, ls, cat, git status...)
- `ssh.exec:git` — git clone/pull/push
- `ssh.exec:file-op` — file writes, deploys
- `ssh.exec:service` — systemctl, service management
- Destructive commands (`rm -rf`, etc.) are **never** granted here —
  they need your explicit time-boxed approval each time.

## Step 5 — Wire the gate

Install the gate on your server (see `install.sh`), then drop the
agent's `ucii_credential.json` next to `gate.py`. The gate will now
ask your UCII server for every command:

```
SSH → gate.py → classify → POST /v1/authorization/delegated/check
                              (signed with agent's ML-DSA-65 key)
                            → allow / deny → audit.log
```

If the server is unreachable, the gate falls back to local
`policy.json` **only** for the owner — everyone else fails closed.

## Step 6 — Verify end-to-end

```bash
/opt/ucii/UCII/.venv/bin/python scripts/verify_wrapping.py \
  --identity-id <id>
```

This signs a fresh message with the agent's key and calls the check
endpoint for each granted operation. All four should return
`authorized=True, state=ACTIVE`.

Then test a real SSH command through the gated key:
```bash
ssh -i ~/.ssh/ucii_gate user@server 'uptime'   # allowed
ssh -i ~/.ssh/ucii_gate user@server 'rm -rf /tmp/x'  # denied
```
Check `/opt/ucii/ucii-agent-gate/audit.log` — decisions should show
`via=ucii-server`.

## Rollback

- **Gate:** delete the `command="..."` prefix from `authorized_keys`. One line.
- **Grant:** revoke via the lifecycle service (see `scripts/revoke_authority.py`).
- **Lifecycle service:** `sudo systemctl disable --now ucii-<name>-lifecycle.service`,
  then remove the user, groups, and credential directory.
- **Identity:** deactivate via the UCII API (identities are never deleted,
  only deactivated — that's by design).

## The standing rule

For UCII identity-server operations, the operator approves each step.
The agent never self-provisions, never self-grants. That's not a
limitation — it's the security model.
