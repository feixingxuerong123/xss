# -*- coding: utf-8 -*-
"""Speed profile of a full-benchmark result file.

Answers one question before any optimisation: WHERE does the wall clock go,
and is it necessary cost or waste?

Reads a benchmark result JSON (``benchmark/results/pNNN_*.json``) and groups
wall clock by case family, then separates two very different shapes:

* request-bound  -- time scales with the number of HTTP requests (fuzzing
  breadth).  Fixable by fewer/shorter requests.
* wait-bound     -- few requests but many seconds each (real-browser DOM
  probes, suite-timeout waits, OOB listening windows).  Fixable only by
  changing the budget/concurrency, not by "sending less".

NOTE (skill section 5): scan_time carries large noise on this host
(+/-25x observed), so read AGGREGATES and QUANTILES, never a single case.

Usage:
    python benchmark/speed_profile.py benchmark/results/p153_full.json
    python benchmark/speed_profile.py <file> --top 25
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict


def family(case_id: str, mode: str) -> str:
    """Best-effort family label: the mode prefix, else the case id stem."""
    mode = (mode or "").lower()
    for key in ("dom", "stored", "blind", "csp", "so2", "importmap",
                "clobber", "proto", "upload", "scenario"):
        if mode.startswith(key):
            return key
    parts = (case_id or "").split("-")
    if len(parts) >= 2:
        return parts[1]
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("result", help="benchmark result JSON")
    ap.add_argument("--top", type=int, default=20,
                    help="how many slowest cases to list")
    args = ap.parse_args()

    with open(args.result, encoding="utf-8") as fh:
        data = json.load(fh)
    cases = data.get("cases") or []
    if not cases:
        print("no cases in", args.result)
        return 1

    total = sum(float(c.get("scan_time_s") or 0.0) for c in cases)
    reqs = sum(int(c.get("requests") or 0) for c in cases)

    groups: dict = defaultdict(list)
    for c in cases:
        groups[family(c.get("case_id", ""), c.get("mode", ""))].append(c)

    print(f"file: {args.result}")
    print(f"cases: {len(cases)} | total wall clock: {total:.0f}s "
          f"| total requests: {reqs}")
    print()

    print(f"{'family':10s} {'n':>4s} {'total_s':>9s} {'share':>7s} "
          f"{'median':>7s} {'mean':>7s} {'max':>7s} {'req/case':>9s} "
          f"{'s/100req':>9s}")
    print("-" * 76)
    rows = []
    for name, cs in groups.items():
        times = [float(c.get("scan_time_s") or 0.0) for c in cs]
        rqs = [int(c.get("requests") or 0) for c in cs]
        g_total = sum(times)
        g_req = sum(rqs)
        rows.append({
            "name": name, "n": len(cs), "total": g_total,
            "share": g_total / total if total else 0.0,
            "median": statistics.median(times),
            "mean": g_total / len(cs),
            "max": max(times),
            "req": g_req / len(cs),
            "s_per_100": (g_total / g_req * 100) if g_req else 0.0,
        })
    for r in sorted(rows, key=lambda x: -x["total"]):
        print(f"{r['name']:10s} {r['n']:4d} {r['total']:9.0f} "
              f"{r['share'] * 100:6.1f}% {r['median']:7.2f} "
              f"{r['mean']:7.2f} {r['max']:7.1f} {r['req']:9.1f} "
              f"{r['s_per_100']:9.1f}")

    print()
    print(f"slowest {args.top} cases (s/100req high => wait-bound, "
          f"low => request-bound):")
    print(f"{'case':18s} {'mode':22s} {'gt':10s} {'time':>7s} "
          f"{'req':>6s} {'s/100req':>9s}")
    print("-" * 76)
    slow = sorted(cases, key=lambda c: -(float(c.get("scan_time_s") or 0)))
    for c in slow[:args.top]:
        t = float(c.get("scan_time_s") or 0)
        r = int(c.get("requests") or 0)
        spr = (t / r * 100) if r else float("nan")
        print(f"{c.get('case_id', ''):18s} {c.get('mode', '')[:22]:22s} "
              f"{c.get('ground_truth', ''):10s} {t:7.1f} {r:6d} "
              f"{spr:9.1f}")
    print()
    # Verdict helper: how much of the clock is in the wait-bound tail?
    top10 = sum(float(c.get("scan_time_s") or 0) for c in slow[:10])
    print(f"top-10 slowest cases hold {top10:.0f}s "
          f"({top10 / total * 100:.0f}% of the run)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
