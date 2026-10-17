Subject: Your UCII Agent Gate credentials — {{AGENT_NAME}} (Audit-only, Monthly)

Hi,

Payment received — your agent "{{AGENT_NAME}}" is now gated under the **Audit-only** plan (monthly billing, $49 CAD/month).

## Your credentials

Keep these safe. Your **control secret** is the human proof — never share it, never put it on your agent's server.

- **Agent identity ID:** `{{IDENTITY_ID}}`
- **Authority ID:** `{{AUTHORITY_ID}}`
- **Control secret:** `{{CONTROL_SECRET}}`
- **Granted operations:** {{OPERATIONS}}
- **Check endpoint:** https://ucii.sportgen-ai.com

Your signing keypair files are attached to this email.

## Setup (5 minutes)

1. Install the gate on your agent's server:
   ```
   curl -sSL https://raw.githubusercontent.com/EtashRhys/ucii-agent-gate/main/install.sh | bash
   ```
2. Register your identity using the attached keypair (see `scripts/register_identity.py`)
3. Open your control panel: https://ucii.sportgen-ai.com/panel/customer-panel.html
4. Paste your Authority ID and Control secret, hit Load

Your panel lets you view status, kill switch, request hall passes, and find your audit log.

## What you got

**Audit-only** means trust but verify. All non-destructive operations are allowed — nothing is denied. Every command is logged to your audit trail, and you can kill the whole thing in one click.

Destructive commands are never standing — use a hall pass ($25) when you need one.

- Monthly billing: $49 CAD/month
- Cancel anytime — revoke the authority, no dark patterns
- Next billing date: {{NEXT_BILLING_DATE}}

## Audit log

Every command your agent runs is logged on **your** server at:
`/opt/ucii/ucii-agent-gate/audit.log`

We never see it, never store it. Generate a clean report anytime:
```
python3 /opt/ucii/ucii-agent-gate/scripts/audit_report.py --days 7
```

Questions? Just reply to this email.

— UCII Admin
