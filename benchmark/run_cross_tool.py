#!/usr/bin/env python
"""Phase 107: cross-tool comparison against THIRD-PARTY detection corpus.

Why this exists
---------------
Our 107-case benchmark plateaus at f1=1.000, but every one of those cases
was designed by us and every fix was made against a case we wrote.  That
is a self-referential loop: it proves we agree with ourselves.

This runner breaks the loop by scoring XSSentinel and third-party tools
against the SAME targets:
  * nuclei-dast-xss  -- ProjectDiscovery's DAST XSS templates: their
                        payloads, their matching, their idea of a finding
  * dalfox           -- if installed
Both are maintained outside this repo, so agreement/disagreement is
evidence about our detection rather than a restatement of our own cases.

Output: per-tool TP/FP/TN/FN + a per-case matrix + disagreement
attribution (who missed what, who claimed what).

Usage
-----
    python benchmark/run_cross_tool.py --out benchmark/results/cross_tool.json
    python benchmark/run_cross_tool.py --ids pos-elem-01,neg-escape-01 ...
    python benchmark/run_cross_tool.py --all        # slow: ~44s/case nuclei
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from benchmark.adapters import get_adapters  # noqa: E402
from benchmark.server import BenchmarkHandler, load_routes  # noqa: E402

# A representative slice: one per vulnerable context family, plus the
# SAFE families that trip reflection-only tools (escaped / comment /
# attribute / CSP / JSONP / encoded RCDATA).
#
# Naming trap: "neg-" here means "a defence is present", NOT "safe".
# neg-rcdata-01..04 and neg-filter-01..03/05/06 are ground-truth
# VULNERABLE (the defence is bypassable); the safe twins carry an
# explicit escape_* mode or a different suffix.
DEFAULT_IDS = [
    # vulnerable -- one per context / defence-bypass family
    "pos-elem-01", "pos-attr-01", "pos-attr-05", "pos-script-01",
    "pos-script-03", "pos-comment-01", "pos-url-01", "pos-dom-01",
    "pos-svg-01", "pos-polyglot-01", "neg-rcdata-01", "neg-filter-01",
    # safe -- where reflection-only tools tend to false-positive
    "neg-escape-01", "neg-comment-01", "neg-attr-01", "neg-csp-01",
    "neg-jsonp-01", "neg-rcdata-05",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        _HERE, "results", "cross_tool.json"))
    ap.add_argument("--md", default=os.path.join(
        _HERE, "results", "cross_tool.md"))
    ap.add_argument("--ids", default="", help="comma-separated case ids")
    ap.add_argument("--all", action="store_true", help="run every case")
    ap.add_argument("--tools", default="XSSentinel,nuclei-dast-xss",
                    help="comma-separated adapter names")
    ap.add_argument("--port", type=int, default=8896)
    args = ap.parse_args()

    man = json.load(open(os.path.join(_HERE, "manifest.json"),
                         encoding="utf-8"))
    all_cases = man["cases"] if isinstance(man, dict) else man
    by_id = {c["id"]: c for c in all_cases}

    if args.all:
        ids = [c["id"] for c in all_cases]
    elif args.ids:
        ids = [s.strip() for s in args.ids.split(",") if s.strip()]
    else:
        ids = DEFAULT_IDS
    cases = [by_id[i] for i in ids if i in by_id]
    missing = [i for i in ids if i not in by_id]
    if missing:
        print(f"[!] unknown case ids: {missing}")

    wanted = {s.strip() for s in args.tools.split(",") if s.strip()}
    adapters = [a for a in get_adapters(only_available=True)
                if a.name in wanted]
    if not adapters:
        print("[!] no requested adapter is available")
        return 1
    print(f"[*] tools: {', '.join(a.name for a in adapters)}")
    print(f"[*] cases: {len(cases)}")

    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{args.port}"
    time.sleep(0.5)

    per_tool: dict[str, dict] = {}
    matrix: dict[str, dict] = {c["id"]: {"ground_truth": c["ground_truth"],
                                        "mode": c["mode"]} for c in cases}
    try:
        for a in adapters:
            print(f"\n[*] {a.name}")
            cm = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0}
            t_start = time.time()
            for c in cases:
                r = a.scan_case(base, c)
                det = bool(r["detected"])
                matrix[c["id"]][a.name] = det
                if r.get("error") in ("timeout",) or (
                        r.get("error") and "not-installed" in str(r["error"])):
                    cm["errors"] += 1
                    mark = "ERR"
                else:
                    gt = c["ground_truth"]
                    if gt == "vulnerable":
                        k = "tp" if det else "fn"
                    else:
                        k = "fp" if det else "tn"
                    cm[k] += 1
                    mark = {"tp": "TP", "fn": "FN", "fp": "FP",
                            "tn": "TN"}[k]
                print(f"    {c['id']:18} gt={c['ground_truth']:10} "
                      f"{mark:3} ({r['time_s']:.1f}s)", flush=True)
            cm["total_time_s"] = round(time.time() - t_start, 1)
            per_tool[a.name] = cm
    finally:
        srv.shutdown()

    # ---- disagreement attribution -------------------------------------
    names = [a.name for a in adapters]
    disagreements = []
    for cid, row in matrix.items():
        gt = row["ground_truth"]
        for name in names:
            if name not in row:
                continue
            det = row[name]
            if gt == "vulnerable" and not det:
                disagreements.append(
                    {"case": cid, "tool": name, "kind": "missed-a-real-XSS"})
            if gt == "safe" and det:
                disagreements.append(
                    {"case": cid, "tool": name, "kind": "false-positive"})

    out = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": base,
        "tools": names,
        "cases": len(cases),
        "per_tool": per_tool,
        "matrix": matrix,
        "disagreements": disagreements,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] saved {args.out}")

    # ---- markdown report ----------------------------------------------
    lines = ["# Cross-tool XSS comparison (third-party corpus)", "",
             f"Generated: {out['generated']}  ",
             f"Targets: {base}  ",
             f"Cases: {len(cases)} (same targets for every tool)", "",
             "| tool | TP | FP | TN | FN | errors | time (s) |",
             "|---|---|---|---|---|---|---|"]
    for n in names:
        c = per_tool[n]
        lines.append(f"| {n} | {c['tp']} | {c['fp']} | {c['tn']} | "
                     f"{c['fn']} | {c['errors']} | {c['total_time_s']} |")
    lines += ["", "## Per-case matrix", "",
              "| case | ground truth | " + " | ".join(names) + " |",
              "|---|---|" + "---|" * len(names)]
    for cid, row in matrix.items():
        cells = []
        for n in names:
            if n not in row:
                cells.append("-")
            else:
                det = row[n]
                gt = row["ground_truth"]
                ok = (det and gt == "vulnerable") or (not det and gt == "safe")
                cells.append(("yes" if det else "no") + ("" if ok else " !"))
        lines.append(f"| {cid} | {row['ground_truth']} | " +
                     " | ".join(cells) + " |")
    lines += ["", "## Disagreements with ground truth", ""]
    if not disagreements:
        lines.append("(none)")
    for d in disagreements:
        lines.append(f"- `{d['case']}`: **{d['tool']}** {d['kind']}")
    with open(args.md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] saved {args.md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
