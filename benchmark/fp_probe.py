"""FP probe: health check for false positives the scorer cannot see.

Phase 160 found the benchmark blind spot: ``_is_detected`` narrowed to
``case["finding_types"]``, so a high-severity finding from another layer was
scored TN (neg-dom-08 carried a ``trusted_types_policy_bypass``).  The scorer
now counts any high/medium/critical finding on a safe case, and this probe is
the belt-and-braces version: it reports EVERY non-info finding per safe case
plus whether the scorer would have counted it, so a future regression in the
scoring rules is visible too.

Run it after touching any detection layer or ``benchmark/runner.py``:
    python -m benchmark.fp_probe [port] [max_payloads] [max_transforms] [timeout]
Defaults: 18899 / 14 / 12 / 90 (the calibrated benchmark口径).
It writes benchmark/results/fp_probe.json.  Severity matters: a `dom` finding
at low is hygiene, not an XSS claim -- check the level, do not assume.
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")

# NOTE: do NOT import from benchmark.run_benchmark_batched -- it parses
# sys.argv at module level and would read our own args as its ENGINE arg.
from http.server import ThreadingHTTPServer  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

from benchmark.server import load_routes, BenchmarkHandler  # noqa: E402
from benchmark.runner import _build_target_url, _invoke_scanner  # noqa: E402
from benchmark.runner import _case_extra_args  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402


def start_server(port: int) -> ThreadingHTTPServer:
    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", port), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import http.client
    for _ in range(40):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/health")
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 200:
                return srv
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("server did not become ready")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18899
    max_p = int(sys.argv[2]) if len(sys.argv) > 2 else 14
    max_t = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 90

    srv = start_server(port)
    base = f"http://127.0.0.1:{port}"
    manifest = json.load(open("benchmark/manifest.json", encoding="utf-8"))
    cases = manifest["cases"] if isinstance(manifest, dict) else manifest
    negs = [c for c in cases if c.get("ground_truth") == "safe"]

    rows = []
    for i, case in enumerate(negs, 1):
        url = _build_target_url(base, case)
        report, elapsed, err = _invoke_scanner(
            url, timeout=timeout, max_payloads=max_p, max_transforms=max_t,
            engine="sync", extra_args=_case_extra_args(base, case))
        findings = (report or {}).get("findings", [])
        noisy = [f for f in findings
                 if f.get("severity", "") != "info"
                 and f.get("type", "") != "fuzzer_triage"]
        declared = set(case.get("finding_types") or [])
        hidden = [f for f in noisy
                  if declared and f.get("type", "") not in declared]
        rows.append({
            "case_id": case["id"],
            "mode": case.get("mode"),
            "all": len(noisy),
            "hidden": len(hidden),
            "types": sorted({f.get("type", "") for f in hidden}),
            "error": err[:80],
        })
        flag = "HIDDEN-FP" if hidden else ("ok" if not noisy else "counted")
        print(f"[{i}/{len(negs)}] {case['id']:<16} {flag:<10} "
              f"all={len(noisy)} hidden={len(hidden)} "
              f"{sorted({f.get('type','') for f in hidden})}", flush=True)

    bad = [r for r in rows if r["hidden"]]
    print("\n=== summary ===")
    print(f"safe cases: {len(rows)}")
    print(f"cases with a finding the benchmark hides: {len(bad)}")
    by_type: dict = {}
    for r in bad:
        for t in r["types"]:
            by_type[t] = by_type.get(t, 0) + 1
    print("hidden findings by type:", json.dumps(by_type, ensure_ascii=False))
    out = os.path.join("benchmark", "results", "fp_probe.json")
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("written:", out)
    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
