#!/bin/bash
# UCII Agent Gate — one-command installer.
#
#   curl -sSL https://raw.githubusercontent.com/EtashRhys/ucii-agent-gate/main/install.sh | bash
#
# What it does:
#   1. Checks for python3.
#   2. Installs the gate into /opt/ucii/ucii-agent-gate (override with GATE_DIR).
#   3. Generates an SSH keypair for your AI agent (or reuses yours with --key).
#   4. Writes a starter policy.json (owner entitlement for your agent).
#   5. Prints the EXACT authorized_keys line to add on your server.
#
# What it does NOT do: touch sshd_config, open ports, or change existing keys.
# Rollback: delete the authorized_keys line. One line.

set -euo pipefail

GATE_DIR="${GATE_DIR:-/opt/ucii/ucii-agent-gate}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== UCII Agent Gate installer =="

command -v python3 >/dev/null || { echo "python3 is required."; exit 1; }

sudo mkdir -p "$GATE_DIR"
sudo cp "$SRC_DIR/gate.py" "$GATE_DIR/gate.py"
sudo cp -r "$SRC_DIR/packages" "$GATE_DIR/packages" 2>/dev/null || true
sudo chmod 755 "$GATE_DIR/gate.py"
[ -f "$GATE_DIR/policy.json" ] || sudo cp "$SRC_DIR/policy.example.json" "$GATE_DIR/policy.json"
[ -f "$GATE_DIR/identity.json" ] || echo '{"note":"run scripts/register_identity.py to bind a UCII AI_AGENT identity"}' | sudo tee "$GATE_DIR/identity.json" >/dev/null
sudo touch "$GATE_DIR/audit.log" && sudo chmod 644 "$GATE_DIR/audit.log"

KEY="$HOME/.ssh/ucii_agent_gate"
if [ ! -f "$KEY" ]; then
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C "ucii-agent-gate" -q
  echo "Generated agent key: $KEY"
else
  echo "Reusing existing key: $KEY"
fi
PUB="$(cat "$KEY.pub")"

echo ""
echo "== DONE — one last step on your server =="
echo "Append this single line to ~/.ssh/authorized_keys on the server"
echo "your AI agent will drive (as the user the agent should run as):"
echo ""
echo "command=\"$GATE_DIR/gate.py\" $PUB"
echo ""
echo "Test it:  ssh -i $KEY user@server 'uptime'"
echo "Deny test: ssh -i $KEY user@server 'rm -rf /tmp/nope'"
echo "Audit log: $GATE_DIR/audit.log"
