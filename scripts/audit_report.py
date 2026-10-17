#!/usr/bin/env python3
"""
UCII Agent Gate — Audit Report Generator.

Reads your agent's local audit log and produces a clean, self-contained
HTML report. Open it in any browser; print to PDF from there if you want
a portable copy.

Your audit log never leaves your server. UCII never sees it.

Usage:
    python3 audit_report.py [options] [output.html]

Options:
    --from YYYY-MM-DD   Only entries on or after this date
    --to YYYY-MM-DD     Only entries on or before this date
    --days N            Only entries from the last N days

Examples:
    python3 audit_report.py --days 7
    python3 audit_report.py --from 2026-10-01 --to 2026-10-15 report.html

Defaults:
    input:  /opt/ucii/ucii-agent-gate/audit.log
    output: ucii-audit-report.html (in the current directory)
"""

import argparse
import json
import sys
import os
from collections import Counter
from datetime import datetime, timedelta, date
from html import escape

DEFAULT_LOG = "/opt/ucii/ucii-agent-gate/audit.log"


def parse_args(argv):
    p = argparse.ArgumentParser(description="UCII audit report generator")
    p.add_argument("output", nargs="?", default="ucii-audit-report.html",
                   help="Output HTML file")
    p.add_argument("--log", default=DEFAULT_LOG,
                   help="Audit log path")
    p.add_argument("--from", dest="from_date", default=None,
                   help="Only entries on or after YYYY-MM-DD")
    p.add_argument("--to", dest="to_date", default=None,
                   help="Only entries on or before YYYY-MM-DD")
    p.add_argument("--days", type=int, default=None,
                   help="Only entries from the last N days")
    args = p.parse_args(argv[1:])

    # Resolve date filters
    from_d = to_d = None
    if args.days is not None:
        to_d = date.today()
        from_d = to_d - timedelta(days=args.days - 1)
    if args.from_date:
        from_d = datetime.strptime(args.from_date, "%Y-%m-%d").date()
    if args.to_date:
        to_d = datetime.strptime(args.to_date, "%Y-%m-%d").date()

    return args.log, args.output, from_d, to_d


def entry_date(e):
    """Extract the date portion of an entry's timestamp."""
    ts = e.get("ts", "")
    try:
        return datetime.fromisoformat(ts.replace("+00:00", "")).date()
    except Exception:
        try:
            return datetime.strptime(ts[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def load_entries(log_path, from_d=None, to_d=None):
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if from_d or to_d:
                d = entry_date(e)
                if d is None:
                    continue
                if from_d and d < from_d:
                    continue
                if to_d and d > to_d:
                    continue
            entries.append(e)
    entries.sort(key=lambda e: e.get("ts", ""))
    return entries


def short_ts(ts_str):
    """Trim an ISO timestamp to HH:MM:SS and the date to YYYY-MM-DD."""
    try:
        # Keep it simple: split on T
        date_part, time_part = ts_str.split("T")
        time_part = time_part.split("+")[0].split(".")[0]
        return date_part, time_part
    except Exception:
        return ts_str[:10], ts_str[11:19]


def build_html(entries, log_path):
    decisions = Counter(e.get("decision", "?") for e in entries)
    classes = Counter(e.get("class", "?") for e in entries)
    dates = sorted({short_ts(e.get("ts", ""))[0] for e in entries if e.get("ts")})
    date_range = f"{dates[0]} to {dates[-1]}" if dates else "—"
    agent = entries[0].get("agent", "—") if entries else "—"
    identity = entries[0].get("identity_id", "—") if entries else "—"

    rows = []
    for e in entries:
        date_part, time_part = short_ts(e.get("ts", ""))
        cmd = escape(e.get("command", ""))
        if len(cmd) > 120:
            cmd = cmd[:117] + "..."
        cls = escape(str(e.get("class", "")))
        dec = e.get("decision", "")
        dec_color = "#0a7a2f" if dec == "allow" else "#b00020"
        reason = escape(str(e.get("reason", "")))
        if len(reason) > 100:
            reason = reason[:97] + "..."
        rows.append(
            f"<tr><td class='mono'>{date_part}<br>{time_part}</td>"
            f"<td class='mono cmd'>{cmd}</td>"
            f"<td>{cls}</td>"
            f"<td><b style='color:{dec_color}'>{dec.upper()}</b></td>"
            f"<td class='reason'>{reason}</td></tr>"
        )

    summary_rows = "".join(
        f"<tr><td>{escape(k)}</td><td><b>{v}</b></td></tr>"
        for k, v in [("Total gate checks", len(entries)),
                     ("Allowed", decisions.get("allow", 0)),
                     ("Denied", decisions.get("deny", 0))]
    )
    class_rows = "".join(
        f"<tr><td>Class: {escape(k)}</td><td><b>{v}</b></td></tr>"
        for k, v in sorted(classes.items())
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UCII Audit Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 1000px;
         margin: 2rem auto; padding: 0 1rem; color: #14181f; background: #fff; }}
  .brand {{ font-size: 1.8rem; font-weight: 800; letter-spacing: .12em; color: #0077cc; }}
  .sub {{ color: #5b6472; margin: .2rem 0 1.2rem; }}
  h2 {{ font-size: 1.1rem; margin: 1.5rem 0 .5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th, td {{ text-align: left; padding: .45rem .5rem; border-bottom: 1px solid #e1e6ee;
            vertical-align: top; }}
  th {{ background: #0b0e14; color: #fff; font-size: .78rem;
        text-transform: uppercase; letter-spacing: .04em; }}
  tr:nth-child(even) td {{ background: #f7f9fc; }}
  .mono {{ font-family: ui-monospace, monospace; font-size: .78rem; }}
  .cmd {{ word-break: break-all; max-width: 340px; }}
  .reason {{ color: #5b6472; font-size: .78rem; max-width: 260px; }}
  .meta {{ color: #5b6472; font-size: .85rem; }}
  .note {{ background: #e8f3ff; border: 1px solid #0077cc; border-radius: 8px;
           padding: .7rem; margin: 1rem 0; font-size: .88rem; }}
  @media print {{ body {{ margin: 0; }} .noprint {{ display: none; }} }}
</style>
</head>
<body>
<div class="brand">UCII</div>
<div class="sub">Agent Audit Report — {escape(agent)}</div>

<div class="note">
  Every command this agent ran through the UCII gate. Generated locally —
  this data never left your server.
</div>

<p class="meta">
  <b>Agent:</b> {escape(agent)} &nbsp;·&nbsp;
  <b>Identity:</b> <span class="mono">{escape(identity)}</span><br>
  <b>Period:</b> {escape(date_range)} &nbsp;·&nbsp;
  <b>Source:</b> <span class="mono">{escape(log_path)}</span>
</p>

<h2>Summary</h2>
<table style="max-width:420px">
  <tbody>{summary_rows}{class_rows}</tbody>
</table>

<h2>Gate Decisions ({len(entries)})</h2>
<table>
  <thead><tr>
    <th>Timestamp</th><th>Command</th><th>Class</th><th>Decision</th><th>Reason</th>
  </tr></thead>
  <tbody>
    {''.join(rows) if rows else "<tr><td colspan='5'>No entries found.</td></tr>"}
  </tbody>
</table>

<p class="meta noprint" style="margin-top:2rem">
  Tip: print this page to PDF from your browser for a portable copy.
</p>
</body>
</html>"""


def main():
    log_path, out_path, from_d, to_d = parse_args(sys.argv)
    if not os.path.isfile(log_path):
        print(f"Audit log not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    entries = load_entries(log_path, from_d, to_d)
    html = build_html(entries, log_path)
    with open(out_path, "w") as f:
        f.write(html)
    filt = ""
    if from_d or to_d:
        filt = f" ({from_d or '...'} to {to_d or '...'})"
    print(f"Report written: {out_path} ({len(entries)} entries{filt})")


if __name__ == "__main__":
    main()
