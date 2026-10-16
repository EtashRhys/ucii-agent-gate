#!/bin/bash
# wrap-agent.sh — wrap an AI agent into the UCII family, step by step.
#
# This walks you (the operator) through the full wrapping:
#   1. keypair generation
#   2. identity provisioning  (needs your approval)
#   3. lifecycle service build
#   4. delegated grant        (needs your approval)
#   5. verification
#
# Run on the UCII server with sudo.
#   sudo bash scripts/wrap-agent.sh
#
set -euo pipefail

VENV_PY="/opt/ucii/UCII/.venv/bin/python"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
PROD_DB="sqlite:////var/lib/ucii/database/pq_auth.db"

echo "== UCII agent wrapping =="
echo "This will create a real AI_AGENT identity on your UCII server."
echo "You approve each consequential step. Nothing is automatic."
echo

read -rp "Agent name (e.g. Rocky): " AGENT_NAME
[ -n "$AGENT_NAME" ]
SLUG=$(echo "$AGENT_NAME" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')
read -rp "Description: " AGENT_DESC
read -rp "Your operator handle: " OPERATOR
WORKDIR="/opt/ucii/ucii-agent-gate"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo
echo "--- Step 1: keypair ---"
"$VENV_PY" - <<'PYEOF'
import base64, hashlib, json, sys
sys.path.insert(0, "/opt/ucii/UCII/.venv/lib/python3.12/site-packages")
import oqs
with oqs.Signature("ML-DSA-65") as sig:
    pub = sig.generate_keypair()
    sec = sig.export_secret_key()
open("agent_public_key.b64", "w").write(base64.b64encode(pub).decode())
cred = {
    "identity_id": "",
    "credential_fingerprint": hashlib.sha256(pub).hexdigest(),
    "private_key_b64": base64.b64encode(sec).decode(),
    "algorithm": "ML-DSA-65",
}
json.dump(cred, open("ucii_credential.json", "w"), indent=2)
import os; os.chmod("ucii_credential.json", 0o600)
print("keypair generated. fingerprint:", cred["credential_fingerprint"][:16], "...")
PYEOF

echo
echo "--- Step 2: provisioning (OPERATOR APPROVAL) ---"
echo "This creates the AI_AGENT identity '$AGENT_NAME' on your PRODUCTION database."
echo "Database: $PROD_DB"
read -rp "Type YES to provision: " CONFIRM
[ "$CONFIRM" = "YES" ] || { echo "aborted."; exit 1; }

command -v systemd-creds >/dev/null || { echo "systemd-creds not found"; exit 1; }
systemd-creds setup 2>/dev/null || true

IDENTITY_ID=$(DATABASE_URL="$PROD_DB" "$VENV_PY" "$SRC_DIR/provision_agent.py" \
  --name "$AGENT_NAME" \
  --description "$AGENT_DESC" \
  --public-key "$WORKDIR/agent_public_key.b64" \
  --granted-by "$OPERATOR" \
  --output-dir "$WORKDIR" | grep '^identity_id:' | awk '{print $2}')
[ -n "$IDENTITY_ID" ] || { echo "provisioning failed"; exit 1; }
echo "identity: $IDENTITY_ID"

# sanity: the API must see it
if ! curl -sf "http://127.0.0.1:8000/v1/identity/$IDENTITY_ID" >/dev/null; then
  echo "ERROR: API cannot see the new identity — wrong database?"
  echo "Expected production DB. Aborting."
  exit 1
fi
echo "API confirms the identity."

# stamp the credential file
"$VENV_PY" -c "
import json
c = json.load(open('$WORKDIR/ucii_credential.json'))
c['identity_id'] = '$IDENTITY_ID'
json.dump(c, open('$WORKDIR/ucii_credential.json','w'), indent=2)
print('credential stamped with identity_id')
"

echo
echo "--- Step 3: lifecycle service ---"
"$VENV_PY" "$SRC_DIR/build_lifecycle_service.py" \
  --identity-id "$IDENTITY_ID" \
  --agent-name "$SLUG" \
  --database-url "$PROD_DB"

echo
echo "--- Step 4: delegated grant (OPERATOR APPROVAL) ---"
echo "Grant $AGENT_NAME: ssh.exec:read, ssh.exec:git, ssh.exec:file-op, ssh.exec:service"
echo "Destructive commands are NEVER granted here."
read -rp "Type YES to grant: " CONFIRM
[ "$CONFIRM" = "YES" ] || { echo "aborted."; exit 1; }

"$VENV_PY" "$SRC_DIR/grant_authority.py" \
  --socket "/run/ucii-$SLUG-lifecycle/lifecycle.sock" \
  --operations ssh.exec:read ssh.exec:git ssh.exec:file-op ssh.exec:service \
  --granted-by "$OPERATOR"

echo
echo "--- Step 5: verification ---"
"$VENV_PY" "$SRC_DIR/verify_wrapping.py" --identity-id "$IDENTITY_ID"

echo
echo "== $AGENT_NAME is wrapped =="
echo "identity_id: $IDENTITY_ID"
echo "Next: install the gate (see install.sh) and place ucii_credential.json beside gate.py."
