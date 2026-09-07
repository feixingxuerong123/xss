# -*- coding: utf-8 -*-
"""Analyze request-count distribution from a req_*.json benchmark run."""
import json
import statistics
import sys


def load(path):
    d = json.load(open(path, encoding="utf-8"))
    return d["meta"], d["cases"], d["counts"]


def pct(vals, p):
    vals = sorted(vals)
    idx = min(len(vals) - 1, int(len(vals) * p))
    return vals[idx]


for path in sys.argv[1:]:
    meta, cases, counts = load(path)
    print("=" * 62)
    print(path, "engine=", meta.get("engine"), "counts=", counts)
    ok = [c for c in cases if not c.get("error")]
    errs = [c for c in cases if c.get("error")]
    for label, group in (("ok", ok), ("error", errs)):
        if not group:
            continue
        reqs = [c.get("requests", 0) for c in group]
        times = [c.get("scan_time_s", 0) for c in group]
        print(f"[{label}] n={len(group)} requests: "
              f"min={min(reqs)} med={int(statistics.median(reqs))} "
              f"p90={pct(reqs, 0.9)} max={max(reqs)} sum={sum(reqs)}")
        print(f"[{label}] n={len(group)} scan_time: "
              f"min={min(times)} med={statistics.median(times):.1f} "
              f"p90={pct(times, 0.9):.1f} max={max(times):.1f} sum={sum(times):.0f}")
    # top request consumers
    rows = sorted(ok, key=lambda c: -c.get("requests", 0))[:12]
    print("-- top-12 by requests --")
    for c in rows:
        print(f"  {c['case_id']:18s} {c['ground_truth'][:4]:4s} "
              f"{c['verdict']:3s} req={c.get('requests', 0):4d} "
              f"t={c.get('scan_time_s', 0):6.1f}s")
    # slowest vs their requests (show the noise)
    slow = sorted(ok, key=lambda c: -c.get("scan_time_s", 0))[:6]
    print("-- top-6 by scan_time (check req count) --")
    for c in slow:
        print(f"  {c['case_id']:18s} {c['ground_truth'][:4]:4s} "
              f"{c['verdict']:3s} req={c.get('requests', 0):4d} "
              f"t={c.get('scan_time_s', 0):6.1f}s")
