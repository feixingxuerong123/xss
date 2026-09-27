#!/usr/bin/env python
"""XSSentinel Accuracy Benchmark — one-click entry point.

Usage:
  python benchmark/run_benchmark.py              # Run XSSentinel-only evaluation
  python benchmark/run_benchmark.py --compare    # Also run dalfox/XSStrike comparison
  python benchmark/run_benchmark.py --quick      # Quick mode (10 cases)
  python benchmark/run_benchmark.py --report     # Generate HTML report after run

Outputs:
  benchmark/results/benchmark_<timestamp>.json   — machine-readable results
  benchmark/results/benchmark_<timestamp>.html   — human-readable report (with --report)
  benchmark/results/comparison_<timestamp>.html  — comparison report (with --compare)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)


def main():
    parser = argparse.ArgumentParser(
        description="XSSentinel Accuracy Benchmark")
    parser.add_argument("--port", type=int, default=18777,
                        help="Benchmark server port (default: 18777)")
    parser.add_argument("--quick", action="store_true",
                        help="Quick mode: only run first 10 cases")
    parser.add_argument("--compare", action="store_true",
                        help="Run横向对比 with dalfox/XSStrike (if installed)")
    parser.add_argument("--report", action="store_true",
                        help="Generate HTML report after evaluation")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--max-payloads", type=int, default=10,
                        help="Max payloads per case (default: 10)")
    parser.add_argument("--max-transforms", type=int, default=6,
                        help="Max transforms per case (default: 6)")
    # There was no --timeout here at all, so the sweep ran on `run_benchmark()`'s
    # 60 s default while `runner.py`'s own CLI advertised 90.  Two full sweeps
    # this session each lost 1-2 negative cases to that budget and then -- because
    # the runner only retries errored *vulnerable* cases -- reported recall and
    # FPR over 183 of 185.  On a loaded host a safe case measured at 10 s took
    # 94 s, so the budget, not the case, was the binding constraint.
    parser.add_argument("--timeout", type=int, default=90,
                        help="Per-case scanner timeout in seconds (default: 90)")
    # Same class of gap as the missing --timeout above: `runner.run_benchmark`
    # has taken an `engine` argument since Phase 43, but this entry point never
    # exposed it -- so `python -m benchmark.run_benchmark` could not measure the
    # async engine at all, which is part of how async accuracy ended up unmeasured.
    parser.add_argument("--engine", choices=["sync", "async"], default="sync",
                        help="Which scanner engine to score (default: sync).")
    args = parser.parse_args()

    # --- Run XSSentinel evaluation via runner ---
    from benchmark.runner import run_benchmark

    result = run_benchmark(
        port=args.port,
        timeout=args.timeout,
        engine=args.engine,
        max_payloads=args.max_payloads,
        max_transforms=args.max_transforms,
        quick=args.quick,
        verbose=args.verbose,
    )

    # --- Optional:横向对比 ---
    if args.compare:
        print("\n[*] Running横向对比 (dalfox / XSStrike)...")
        from benchmark.adapters import get_adapters, run_comparison
        from benchmark.server import load_routes, BenchmarkHandler
        from http.server import HTTPServer
        import threading

        adapters = get_adapters(only_available=True)
        print(f"    Available tools: {[a.name for a in adapters]}")

        if len(adapters) > 1:
            # Start server for comparison tools
            port = args.port + 1
            routes = load_routes()
            BenchmarkHandler.routes = routes
            server = HTTPServer(("127.0.0.1", port), BenchmarkHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            time.sleep(0.5)
            base_url = f"http://127.0.0.1:{port}"

            # Load manifest
            manifest_path = os.path.join(_HERE, "manifest.json")
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            cases = manifest["cases"]
            if args.quick:
                cases = cases[:10]

            comparison = run_comparison(
                base_url, cases, adapters=adapters, verbose=args.verbose)

            # Print comparison table
            print("\n" + "=" * 64)
            print("  Tool Comparison")
            print("=" * 64)
            print(f"  {'Tool':<12} {'Recall':>8} {'FPR':>8} {'F1':>8} "
                  f"{'ERR':>4} {'Time':>8}")
            print("  " + "-" * 52)
            for name, metrics in comparison.items():
                print(f"  {name:<12} {metrics['recall']:>7.2%} "
                      f"{metrics['fpr']:>7.2%} {metrics['f1']:>7.4f} "
                      f"{metrics.get('errors', 0):>4} "
                      f"{metrics['total_time_s']:>7.1f}s")
            print("=" * 64)

            # Save comparison results
            out_dir = os.path.join(_HERE, "results")
            os.makedirs(out_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            comp_path = os.path.join(out_dir, f"comparison_{ts}.json")
            with open(comp_path, "w", encoding="utf-8") as f:
                json.dump(comparison, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Comparison saved: {comp_path}")

            # Comparison HTML (docstring promise; generate_comparison_html
            # expects a list of dicts each carrying a "tool" key)
            try:
                from benchmark.report import generate_comparison_html
                tool_rows = [dict(metrics, tool=name)
                             for name, metrics in comparison.items()]
                html_str = generate_comparison_html(tool_rows)
                comp_html_path = os.path.join(out_dir,
                                              f"comparison_{ts}.html")
                with open(comp_html_path, "w", encoding="utf-8") as f:
                    f.write(html_str)
                print(f"[+] Comparison HTML: {comp_html_path}")
            except Exception as e:  # noqa: BLE001
                print(f"[!] Comparison HTML generation failed: {e}")

            server.shutdown()
        else:
            print("    [!] Only XSSentinel available. Install dalfox/XSStrike "
                  "for comparison.")
            print("        dalfox: https://github.com/hahwul/dalfox/releases")
            print("        XSStrike: git clone https://github.com/s0md3v/XSStrike")

    # --- Persist machine-readable results (docstring promise) ---
    out_dir = os.path.join(_HERE, "results")
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(out_dir, f"benchmark_{ts}.json")
    result_dict = {
        "tool": result.tool,
        # Which engine produced these numbers.  Without it a sync headline and an
        # async headline are the same file apart from their timestamps, and the
        # two are NOT comparable (see the sync-TP / async-FN on pos-cdata-01).
        "engine": result.engine,
        "timestamp": result.timestamp,
        "total_cases": result.total_cases,
        "total_time_s": result.total_time_s,
        "tp": result.tp, "fp": result.fp,
        "tn": result.tn, "fn": result.fn,
        "recall": result.recall, "precision": result.precision,
        "fpr": result.fpr, "f1": result.f1,
        "errors": getattr(result, "errors", None),
        # Skipped cases are a hole in the denominator, and recall/precision are
        # computed over what RAN (runner.py:569-570).  Printing only tp/fp/tn/fn
        # lets a run that scored 185 of 192 cases read as a clean sweep, so the
        # count that explains the gap has to sit next to the rates.
        "skipped": sum(1 for c in result.cases if c["verdict"] == "SKIP"),
        "scored": sum(1 for c in result.cases
                      if c["verdict"] in ("TP", "FP", "TN", "FN")),
        # How much of this sweep only produced an answer after a re-measure.  A
        # run with 192 verdicts and 12 retries is a much less healthy machine than
        # one with no retries, and the rates alone cannot tell them apart.
        "retried_cases": sum(1 for c in result.cases if c.get("retries")),
        # Rows that STILL report zero traffic after the retries.  Such a case
        # answered nothing about the scanner, and without this line `fn: 6`
        # reads as six detection misses when some of them are unresolved
        # environment failures (Phase 176t measured three at 11.2-11.9s each,
        # with error='' -- the scanner's own --timeout 10 expiring inside the
        # scan, which never surfaces as a harness error).
        "zero_request_rows": sum(1 for c in result.cases
                                 if not c.get("requests")
                                 and c["verdict"] != "SKIP"),
        "by_context": result.by_context,
        "false_positives": result.false_positives,
        "false_negatives": result.false_negatives,
        # Per-case rows, minus the finding bodies.  An aggregate that says
        # `errors: 1` without saying WHICH case forces a full re-run -- 18 minutes
        # on this machine -- to answer a question the runner already had in
        # memory; the last sweep had two such cases and both were hunted by hand.
        "cases": [{k: v for k, v in c.items() if k != "finding_details"}
                  for c in result.cases],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result_dict, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved: {json_path}")

    # --- Optional: HTML report ---
    if args.report:
        try:
            from benchmark.report import generate_html
            html_path = os.path.join(out_dir, f"benchmark_{ts}.html")
            # generate_html RETURNS the HTML string (does not write files)
            html = generate_html(result_dict)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[+] HTML report: {html_path}")
        except Exception as e:
            print(f"[!] HTML report generation failed: {e}")

    # --- Quality gate ---
    if result.fpr > 0.20 or result.recall < 0.50:
        print("\n[!] Quality gate FAILED (FPR>20% or Recall<50%)")
        return 1
    else:
        print("\n[+] Quality gate PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
