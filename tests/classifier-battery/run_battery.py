#!/usr/bin/env python3
"""
Verdict-only harness v2 for the UCII gate classifier attack battery.

Usage: python3 run_battery.py <gate-file> <label>

Calls the gate's pure classification + decision functions with stubbed
UCII server answers. Nothing is executed, no SSH, no server contact.

Profiles:
  A = Restricted customer, grant {read}
  B = Restricted customer, grants {read, git}
  C = owner local fallback (server check unavailable, owner entitlement)
      Scored on honesty: an attack passes C only if it is denied OR its
      class label is at least its honest minimum. Destructive-minimum
      items must be denied outright.
  D = grants-only local fallback (no entitlement, one explicit grant
      per item) — the grant-scoping battleground.
"""
import hashlib
import importlib.util
import json
import sys

sys.path.insert(0, ".")
from corpus import ITEMS

GATE_PATH = sys.argv[1]
LABEL = sys.argv[2]
RANK = {"destructive": 6, "unclassified": 5, "service": 4,
        "file-op": 3, "git": 2, "read": 1, "empty": 0}
GRANTS = {"A": {"read"}, "B": {"read", "git"}}
PROFILES = ("A", "B", "C", "D")

spec = importlib.util.spec_from_file_location("gate_under_test", GATE_PATH)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
gate_sha = hashlib.sha256(open(GATE_PATH, "rb").read()).hexdigest()


def run_profile(item, profile):
    cmd = item["cmd"]
    if profile in GRANTS:
        granted = GRANTS[profile]
        gate.ucii_check = lambda c, cls: (
            (True, "granted (stub)") if cls in granted
            else (False, "not granted (stub)"))
        allowed, reason, via, cls = gate.decide(cmd, "battery")
        return allowed, reason
    # fallback profiles: server check unavailable
    gate.ucii_check = lambda c, cls: None
    grants = []
    if item.get("grant_pattern"):
        grants.append({"agent": "battery", "id": "test-grant",
                       "command_pattern": item["grant_pattern"],
                       "expires_at": "2099-01-01T00:00:00+00:00"})
    entitlement = "owner" if profile == "C" else "none"
    policy = {"agents": {"battery": {"entitlement": entitlement}},
              "grants": grants}
    orig_load = gate.load_json
    gate.load_json = lambda path, default: (
        policy if str(path).endswith("policy.json") else default)
    try:
        allowed, reason, via, cls = gate.decide(cmd, "battery")
    finally:
        gate.load_json = orig_load
    return allowed, reason


results = []
for item in ITEMS:
    actual_class = gate.classify(item["cmd"])
    row = {"id": item["id"], "cat": item["cat"], "cmd": item["cmd"],
           "effect": item["effect"], "min_class": item["min_class"],
           "actual_class": actual_class,
           "under_classified": RANK[actual_class] < RANK[item["min_class"]],
           "scored": item.get("scored", True), "profiles": {}}
    for profile in PROFILES:
        allowed, reason = run_profile(item, profile)
        expect = None
        if profile in item.get("deny_in", []):
            expect = "deny"
        elif profile in item.get("allow_in", []):
            expect = "allow"
        verdict = None
        if expect == "deny":
            if not allowed:
                verdict = "PASS"
            elif profile == "C" and RANK[actual_class] >= RANK[item["min_class"]]:
                verdict = "PASS"  # allowed, but honestly labeled (owner may)
            else:
                verdict = "FAIL-ALLOWED"
        elif expect == "allow":
            verdict = "PASS" if allowed else "FAIL-DENIED"
        row["profiles"][profile] = {"allowed": allowed, "expect": expect,
                                    "verdict": verdict, "reason": reason}
    results.append(row)

scored = [r for r in results if r["scored"]]
fails = {p: [] for p in PROFILES}
false_denies = []
for r in scored:
    for p in PROFILES:
        v = r["profiles"][p]["verdict"]
        if v == "FAIL-ALLOWED":
            fails[p].append(r["id"])
        elif v == "FAIL-DENIED":
            false_denies.append((r["id"], p))
under = [r["id"] for r in scored if r["under_classified"]]

summary = {"gate_file": GATE_PATH, "gate_sha256": gate_sha,
           "items_total": len(results), "items_scored": len(scored),
           "items_recorded_only": len(results) - len(scored),
           "under_classified_items": under, "fail_allowed": fails,
           "false_denies": false_denies}
with open(f"results-{LABEL}.json", "w") as f:
    json.dump({"summary": summary, "results": results}, f, indent=1)

lines = [f"# Attack Battery Results — {LABEL}",
         f"Gate under test: {GATE_PATH}, sha256 `{gate_sha}`",
         f"Items: {len(results)} total, {len(scored)} scored, "
         f"{len(results) - len(scored)} recorded-only (category 9)", "",
         "## Headline scores (scored items)"]
for p in PROFILES:
    lines.append(f"- Profile {p}: {len(fails[p])} security FAILs: {fails[p]}")
lines.append(f"- False denies (benign work blocked): {false_denies}")
lines.append(f"- Under-classified raw items: {len(under)} — {under}")
lines += ["", "## Every FAIL, in detail"]
for r in scored:
    bad = [(p, r["profiles"][p]) for p in PROFILES
           if r["profiles"][p]["verdict"] in ("FAIL-ALLOWED", "FAIL-DENIED")]
    if not bad:
        continue
    lines.append(f"### {r['id']} — `{r['cmd']}`")
    lines.append(f"Effect: {r['effect']} · honest minimum: {r['min_class']} · "
                 f"classifier said: **{r['actual_class']}**")
    for p, pr in bad:
        lines.append(f"- Profile {p}: {pr['verdict']} (reason: {pr['reason']})")
    lines.append("")
lines += ["## Full item table",
          "| id | command | min | actual | A | B | C | D |",
          "|---|---|---|---|---|---|---|---|"]
for r in results:
    def cell(p):
        pr = r["profiles"][p]
        got = "allow" if pr["allowed"] else "deny"
        return f"{got}{'' if pr['verdict'] in (None, 'PASS') else ' ✗'}"
    cmd = r["cmd"].replace("|", "\\|").replace("\n", "⏎")
    lines.append(f"| {r['id']} | `{cmd}` | {r['min_class']} | "
                 f"{r['actual_class']} | {cell('A')} | {cell('B')} | "
                 f"{cell('C')} | {cell('D')} |")
with open(f"results-{LABEL}.md", "w") as f:
    f.write("\n".join(lines) + "\n")

print(json.dumps(summary, indent=1))
