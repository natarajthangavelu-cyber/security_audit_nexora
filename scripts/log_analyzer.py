#!/usr/bin/env python3
"""
log_analyzer.py - Simulated authentication-log analyser for the Nexora audit.

Detects:
  1. Password-spray  : one source IP failing against many DIFFERENT usernames
  2. Brute force     : one source IP failing many times against ONE username
  3. Compromise      : a successful login from an IP that earlier produced many failures

Usage:
    python scripts/log_analyzer.py evidence/sample_auth.log
    python scripts/log_analyzer.py evidence/sample_auth.log --spray-users 10 --brute-fails 15 --csv data/log_findings.csv

Log format (one event per line):
    2026-09-14T01:12:05,185.220.101.34,user23@nexora.example,FAILURE
"""
import argparse, csv, sys
from collections import defaultdict
from datetime import datetime

def parse(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ts, ip, user, result = [x.strip() for x in line.split(",")]
                events.append((datetime.fromisoformat(ts), ip, user, result.upper()))
            except ValueError:
                print(f"[warn] skipping malformed line {n}: {line}", file=sys.stderr)
    return events

def analyse(events, spray_users, brute_fails):
    fails = defaultdict(list)      # ip -> [(ts, user)]
    success = defaultdict(list)    # ip -> [(ts, user)]
    for ts, ip, user, res in events:
        (fails if res == "FAILURE" else success)[ip].append((ts, user))
    findings = []
    for ip, rows in fails.items():
        users = {u for _, u in rows}
        first, last = min(t for t, _ in rows), max(t for t, _ in rows)
        if len(users) >= spray_users:
            verdict = "Password spray"
        elif len(rows) >= brute_fails and len(users) == 1:
            verdict = "Brute force"
        else:
            continue
        hits = [(t, u) for t, u in success.get(ip, []) if t >= first]
        findings.append({
            "source_ip": ip, "failed_logins": len(rows), "distinct_users": len(users),
            "first_seen": first.isoformat(sep=" "), "last_seen": last.isoformat(sep=" "),
            "verdict": verdict,
            "successful_after_failures": len(hits),
            "accounts_compromised": ";".join(sorted({u for _, u in hits})),
        })
    return sorted(findings, key=lambda f: -f["failed_logins"])

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile")
    ap.add_argument("--spray-users", type=int, default=10, help="distinct users from one IP to flag spray (default 10)")
    ap.add_argument("--brute-fails", type=int, default=15, help="failures against one user to flag brute force (default 15)")
    ap.add_argument("--csv", help="write findings to this CSV file")
    a = ap.parse_args()
    ev = parse(a.logfile)
    res = analyse(ev, a.spray_users, a.brute_fails)
    print(f"Events analysed: {len(ev)} | Suspicious sources: {len(res)}\n")
    hdr = f"{'Source IP':<18}{'Fails':>6}{'Users':>7}  {'Verdict':<16}{'Success after':>14}  Accounts"
    print(hdr); print("-" * len(hdr))
    for f in res:
        print(f"{f['source_ip']:<18}{f['failed_logins']:>6}{f['distinct_users']:>7}  {f['verdict']:<16}{f['successful_after_failures']:>14}  {f['accounts_compromised']}")
    if a.csv and res:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=res[0].keys()); w.writeheader(); w.writerows(res)
        print(f"\nCSV written to {a.csv}")

if __name__ == "__main__":
    main()
