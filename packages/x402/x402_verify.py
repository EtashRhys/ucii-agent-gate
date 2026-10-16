"""
x402 pay-per-use verification for the UCII Agent Gate.

x402 (Coinbase open standard) lets an API server demand a small USDC
payment per call. Flow:

  1. Agent attempts a metered command through the gate.
  2. Gate calls verify_payment() with the receipt the agent presented
     (passed as the UCII_X402_RECEIPT env var by the agent's client).
  3. This module checks the receipt against a facilitator.

PRODUCTION INTEGRATION (required before charging real money):
  - Run or choose an x402 facilitator (see https://github.com/coinbase/x402).
  - Set the facilitator URL + accepted asset/network in policy.json under
    policy["x402"] = {"facilitator_url": ..., "asset": "USDC",
                      "network": "base", "prices": {"read": "0.001", ...}}.
  - Replace the stub below with a real facilitator verify call:
    POST {facilitator_url}/verify  {paymentPayload, paymentRequirements}

Until then, verify_payment() runs in DRY-RUN mode: it validates the
receipt *shape* and logs the would-be charge, but never fails closed on
payment — it fails closed on *verifier errors* only. Flip DRY_RUN to False
once the facilitator is wired.
"""

import json
import os

DRY_RUN = True


def verify_payment(receipt, cmd_class, policy):
    """
    Returns (ok: bool, detail: str).
    Never raises: the gate treats exceptions as deny.
    """
    cfg = policy.get("x402", {})
    prices = cfg.get("prices", {})

    if not receipt:
        return False, "no payment receipt presented"

    try:
        r = json.loads(receipt) if isinstance(receipt, str) else receipt
    except Exception:
        return False, "receipt is not valid JSON"

    if "paymentPayload" not in r or "paymentRequirements" not in r:
        return False, "receipt missing x402 fields"

    price = prices.get(cmd_class, prices.get("default", "0.001"))

    if DRY_RUN:
        return True, "dry-run: would charge %s USDC for class '%s'" % (
            price, cmd_class)

    # ---- production path: ask the facilitator ----
    import urllib.request
    req = urllib.request.Request(
        cfg["facilitator_url"].rstrip("/") + "/verify",
        data=json.dumps({
            "paymentPayload": r["paymentPayload"],
            "paymentRequirements": r["paymentRequirements"],
        }).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
    except Exception as e:
        return False, "facilitator unreachable: %s" % e

    if result.get("isValid"):
        return True, "paid %s USDC for class '%s'" % (price, cmd_class)
    return False, "facilitator rejected payment: %s" % result.get(
        "invalidReason", "unknown")
