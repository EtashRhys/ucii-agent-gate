# Package: x402 pay-per-use

For the sophisticated developer who'd rather pay per command than
subscribe. Built on [x402](https://github.com/coinbase/x402) (Coinbase
open standard): the agent attaches a tiny USDC payment to each metered
command, the gate verifies it with a facilitator, then executes.

## How it works

1. The owner adds the agent to `policy.json`:

```json
"agents": {
  "dev-agent-7": { "entitlement": "x402" }
},
"x402": {
  "facilitator_url": "https://your-facilitator.example.com",
  "asset": "USDC",
  "network": "base",
  "prices": {
    "read": "0.001",
    "git": "0.01",
    "file-op": "0.01",
    "service": "0.05",
    "default": "0.01"
  }
}
```

2. The agent's client presents the payment receipt as the
`UCII_X402_RECEIPT` env var when opening the SSH session
(its x402 client library builds this — see the x402 docs).

3. The gate calls `packages/x402/x402_verify.py`, which POSTs the
receipt to the facilitator's `/verify` endpoint. Valid → execute.
Invalid/missing → deny + log.

## Status

The verifier ships in **dry-run mode**: it validates receipt shape and
logs the would-be charge without failing on payment. Flip `DRY_RUN`
to `False` in `x402_verify.py` once your facilitator is wired —
the production path is already written, it just needs your URL.

## When to offer which package

- **Entitlement (flat-rate):** the agent works for you daily — a dev
  station, an ops assistant, a deploy bot. Predictable cost.
- **x402 (pay-per-use):** occasional or bursty use, or a developer
  who wants zero commitment. They pay exactly what they burn.
