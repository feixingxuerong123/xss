"""Performance benchmark suite for XSSentinel (Phase 26-3).

Measures scanner throughput, per-endpoint latency, memory footprint, and
detection-layer coverage against the local vulnerable test server.  The
benchmark is deterministic (fixed endpoint set, fixed payload budget) so
results are comparable across runs.

Usage (standalone)::

    python tests/benchmark.py
    python tests/benchmark.py --json benchmark_report.json
    python tests/benchmark.py --rounds 3      # median of 3 runs

Usage (pytest)::

    pytest tests/test_benchmark.py -v

Metrics recorded:

  * **wall_time_s**       -- total scan wall-clock time (seconds)
  * **requests_made**     -- total HTTP requests issued by the scanner
  * **req_per_s**         -- requests / wall_time
  * **endpoints_scanned** -- number of endpoints in the benchmark set
  * **eps**               -- endpoints / wall_time
  * **findings**          -- total findings discovered
  * **findings_per_s**    -- findings / wall_time
  * **payloads_dispatched** -- total payload variants sent
  * **layers_fired**      -- distinct detection layers that ran
  * **mem_delta_mb**      -- memory delta (RSS) from before to after scan
  * **per_endpoint**      -- per-URL timing + request count

The benchmark also records a "quality" dimension: the number of distinct
detection layers that fired and the false-positive rate on /safe.  A
scanner that is fast but misses vulnerabilities or produces false
positives is not "performant" in any meaningful sense.
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import statistics
import sys
import threading
import time
import tracemalloc
from typing import Callable

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner
from xssentinel.core.oob import SelfHostedListener

# Import the vulnerable server to start it in-process.
from tests import vuln_server


BASE = "http://127.0.0.1:8899"
# 8899 sits inside the Windows dynamic-reservation kill zone (netsh
# excludedportrange: 8810-9109 on this host as of 2026-09-27) -- binds
# fail with WinError 10013 there.  18899 is outside every observed range.
BENCH_PORT = 18899

# A representative subset of endpoints that exercises every detection
# layer without being so large the benchmark takes minutes.  Each entry:
# (path, method, params, data)
BENCHMARK_ENDPOINTS = [
    ("/echo",        "GET", {"q": "bench"}, {}),
    ("/attr",        "GET", {"q": "bench"}, {}),
    ("/script",      "GET", {"q": "bench"}, {}),
    ("/href",        "GET", {"q": "bench"}, {}),
    ("/evt",         "GET", {"q": "bench"}, {}),
    ("/dom",         "GET", {}, {}),
    ("/safe",        "GET", {"q": "bench"}, {}),
    ("/waf",         "GET", {"q": "bench"}, {}),
    ("/cdata",       "GET", {"q": "bench"}, {}),
    ("/meta",        "GET", {"q": "bench"}, {}),
    ("/tpl",         "GET", {"q": "bench"}, {}),
    ("/mxss",        "GET", {"q": "bench"}, {}),
    ("/clobber",     "GET", {"q": "bench"}, {}),
    ("/tpl-eval",    "GET", {"q": "bench"}, {}),
    ("/jsonp",       "GET", {"callback": "bench"}, {}),
    ("/csp-weak",    "GET", {"q": "bench"}, {}),
    ("/css",         "GET", {"q": "bench"}, {}),
    ("/comment",     "GET", {"q": "bench"}, {}),
    ("/postmsg",     "GET", {}, {}),
    ("/proto",       "GET", {"q": "{}"}, {}),
    ("/sw",          "GET", {"q": "x.js"}, {}),
    ("/worker",      "GET", {"q": "x.js"}, {}),
    ("/redirect",    "GET", {"url": "x"}, {}),
    ("/react",       "GET", {"q": "bench"}, {}),
    ("/header-reflect", "GET", {}, {}),
    ("/path-reflect",   "GET", {}, {}),
    ("/cookie-reflect", "GET", {}, {}),
    ("/error-404",   "GET", {}, {}),
    ("/markdown",    "GET", {"q": "![x](x)"}, {}),
    ("/graphql-app", "GET", {}, {}),
    ("/ws-app",      "GET", {}, {}),
    ("/ws-insecure", "GET", {}, {}),
]


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

_server_thread: threading.Thread | None = None
_server: object | None = None


_OWNER_PROBE = "/echo?q=xssentinel_owner_probe"


def _we_own_the_port() -> bool:
    """True only if OUR fixture handler answered, not just "something answered"."""
    import http.client
    try:
        conn = http.client.HTTPConnection("127.0.0.1", BENCH_PORT, timeout=5)
        conn.request("GET", _OWNER_PROBE)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        conn.close()
        return resp.status == 200 and "xssentinel_owner_probe" in body
    except Exception:
        return False


def ensure_server() -> None:
    """Start the vulnerable test server in a background thread (once).

    Ownership is PROBED, not assumed.  `HTTPServer.allow_reuse_address` is on,
    and on Windows `SO_REUSEADDR` lets the bind SUCCEED even when another
    process already holds the port -- traffic then keeps going to that other
    server.  Measured consequence: the benchmark scanned a foreign listener on
    8899, reported `requests_made > 0` with `payloads_dispatched == 0` and an
    empty `findings_by_type`, and because this fixture is module-scoped the bad
    dict was reused for every dependent test, so one transient looked like four
    reproducible code failures (and a retry could not heal it).  Fail loudly
    here instead of measuring somebody else's app.
    """
    global _server_thread, _server
    if _server is not None:
        return
    from http.server import HTTPServer
    try:
        _server = HTTPServer(("127.0.0.1", BENCH_PORT),
                             vuln_server.H)
    except OSError as exc:
        raise RuntimeError(
            "cannot bind the xssentinel fixture server on 127.0.0.1:%d (%s); "
            "something else holds it -- close it or point BENCH_PORT elsewhere"
            % (BENCH_PORT, exc)) from exc
    _server_thread = threading.Thread(target=_server.serve_forever,
                                      daemon=True)
    _server_thread.start()
    # Give the server a moment to bind.
    time.sleep(0.2)
    if not _we_own_the_port():
        _server.shutdown()
        _server.server_close()
        _server, _server_thread = None, None
        raise RuntimeError(
            "127.0.0.1:%d is answered by another process, not by this fixture "
            "server (the bind succeeded anyway -- Windows SO_REUSEADDR allows "
            "that). Refusing to benchmark a foreign server: it produces zero "
            "payloads and empty findings that look like a detection regression."
            % BENCH_PORT)


def stop_server() -> None:
    """Shut down the test server (call at end of benchmark session)."""
    global _server_thread, _server
    if _server is not None:
        _server.shutdown()
        _server.server_close()
        _server = None
        _server_thread = None


# ---------------------------------------------------------------------------
# Memory measurement (cross-platform RSS)
# ---------------------------------------------------------------------------

def _rss_mb() -> float:
    """Return current process RSS in MB, or 0.0 if unavailable."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        pass
    # Fallback: tracemalloc (Python-level, not true RSS but still useful
    # for detecting allocation leaks).
    try:
        current, _peak = tracemalloc.get_traced_memory()
        return current / (1024 * 1024)
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Core benchmark
# ---------------------------------------------------------------------------

def run_benchmark(
    endpoints: list[tuple[str, str, dict, dict]] | None = None,
    max_payloads: int = 14,
    label: str = "default",
    oob_timeout: int = 8,
    include_stored: bool = True,
    max_transforms: int = 12,
) -> dict:
    """Run a single benchmark pass and return a metrics dict.

    Args:
        endpoints: list of (path, method, params, data).  Defaults to
            BENCHMARK_ENDPOINTS.
        max_payloads: payload budget per parameter.
        label: human-readable label for this run.
        oob_timeout: seconds to wait for blind-XSS OOB callbacks.
        include_stored: whether to run the stored-XSS pass.
        max_transforms: WAF-evasion transform budget (lower = faster CI).
    """
    ensure_server()
    eps = endpoints or BENCHMARK_ENDPOINTS

    # Force a GC + start memory tracing so mem_delta is meaningful.
    gc.collect()
    tracemalloc_start = False
    if not tracemalloc.is_tracing():
        tracemalloc.start()
        tracemalloc_start = True
    mem_before = _rss_mb()

    req = Requester(timeout=10)
    oob = SelfHostedListener(host="127.0.0.1")
    sc = Scanner(
        requester=req,
        verbose=False,
        oob=oob,
        max_payloads=max_payloads,
        max_transforms=max_transforms,
        dom_engine="static",  # deterministic; no Playwright dependency
    )

    per_endpoint: list[dict] = []
    t_start = time.perf_counter()

    for path, method, params, data in eps:
        url = BASE + path
        t0 = time.perf_counter()
        sc.scan_endpoint(url, method, params, data)
        dt = time.perf_counter() - t0
        per_endpoint.append({
            "path": path,
            "method": method,
            "time_s": round(dt, 4),
            "requests": sc.requests_made,
        })

    # Stored XSS pass.
    if include_stored:
        t0 = time.perf_counter()
        sc.scan_stored(BASE + "/store", view_url=BASE + "/view",
                       method="POST", param="q")
        stored_time = time.perf_counter() - t0
    else:
        stored_time = 0.0

    # Blind OOB collection.
    t0 = time.perf_counter()
    sc.collect_oob(timeout=oob_timeout)
    oob_time = time.perf_counter() - t0

    wall_time = time.perf_counter() - t_start
    mem_after = _rss_mb()

    if tracemalloc_start:
        tracemalloc.stop()

    # Aggregate findings.
    findings = sc.findings
    by_type: dict[str, int] = {}
    for f in findings:
        t = f.data.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    safe_findings = [f for f in findings
                     if f.data.get("url", "").endswith("/safe")]

    # Coverage summary.
    cov = sc.coverage.summary()
    layers_fired = sum(1 for v in cov["layer_coverage"].values() if v > 0)
    total_layers = len(cov["layer_coverage"])

    result = {
        "label": label,
        "max_payloads": max_payloads,
        "wall_time_s": round(wall_time, 4),
        "stored_xss_time_s": round(stored_time, 4),
        "oob_collect_time_s": round(oob_time, 4),
        "requests_made": sc.requests_made,
        "req_per_s": round(sc.requests_made / wall_time, 2) if wall_time > 0 else 0,
        "endpoints_scanned": len(eps),
        "eps": round(len(eps) / wall_time, 2) if wall_time > 0 else 0,
        "findings_count": len(findings),
        "findings_per_s": round(len(findings) / wall_time, 2) if wall_time > 0 else 0,
        "payloads_dispatched": cov["totals"]["payloads_dispatched"],
        "layers_fired": layers_fired,
        "total_layers": total_layers,
        "layer_coverage_pct": round(100 * layers_fired / total_layers, 1) if total_layers else 0,
        "false_positives_on_safe": len(safe_findings),
        "mem_before_mb": round(mem_before, 2),
        "mem_after_mb": round(mem_after, 2),
        "mem_delta_mb": round(mem_after - mem_before, 2),
        "waf_detected": sc.waf_name,
        "findings_by_type": by_type,
        "per_endpoint": per_endpoint,
    }
    return result


def run_multi(rounds: int = 3, **kwargs) -> dict:
    """Run the benchmark multiple times and return median metrics.

    The per-endpoint timing from the median run is kept; aggregate
    metrics (wall_time, req_per_s, etc.) are reduced to median + stdev.
    """
    results = [run_benchmark(label=f"round_{i+1}", **kwargs) for i in range(rounds)]

    # Pick the median by wall_time.
    sorted_results = sorted(results, key=lambda r: r["wall_time_s"])
    median_idx = len(sorted_results) // 2
    median = sorted_results[median_idx]

    wall_times = [r["wall_time_s"] for r in results]
    req_per_s = [r["req_per_s"] for r in results]

    median["multi_round"] = {
        "rounds": rounds,
        "wall_time_median_s": round(statistics.median(wall_times), 4),
        "wall_time_stdev_s": round(statistics.stdev(wall_times), 4) if len(wall_times) > 1 else 0,
        "req_per_s_median": round(statistics.median(req_per_s), 2),
        "req_per_s_stdev": round(statistics.stdev(req_per_s), 2) if len(req_per_s) > 1 else 0,
        "all_wall_times": wall_times,
    }
    median["label"] = "median"
    return median


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_report(result: dict) -> str:
    """Format a benchmark result as a human-readable console summary."""
    lines = []
    lines.append("=" * 64)
    lines.append("  XSSentinel Performance Benchmark")
    lines.append("=" * 64)
    lines.append(f"  Label:             {result['label']}")
    lines.append(f"  Endpoints scanned: {result['endpoints_scanned']}")
    lines.append(f"  Max payloads/param:{result['max_payloads']}")
    lines.append("")
    lines.append("  --- Throughput ---")
    lines.append(f"  Wall time:         {result['wall_time_s']:.3f}s")
    lines.append(f"  HTTP requests:     {result['requests_made']}")
    lines.append(f"  Requests/sec:      {result['req_per_s']:.1f}")
    lines.append(f"  Endpoints/sec:     {result['eps']:.1f}")
    lines.append(f"  Payloads sent:     {result['payloads_dispatched']}")
    lines.append("")
    lines.append("  --- Detection ---")
    lines.append(f"  Findings:          {result['findings_count']}")
    lines.append(f"  Findings/sec:      {result['findings_per_s']:.1f}")
    lines.append(f"  Layers fired:      {result['layers_fired']}/{result['total_layers']} ({result['layer_coverage_pct']}%)")
    lines.append(f"  False positives:   {result['false_positives_on_safe']} (on /safe)")
    lines.append(f"  WAF detected:      {result['waf_detected'] or 'none'}")
    lines.append(f"  By type:           {result['findings_by_type']}")
    lines.append("")
    lines.append("  --- Memory ---")
    lines.append(f"  Before:            {result['mem_before_mb']:.1f} MB")
    lines.append(f"  After:             {result['mem_after_mb']:.1f} MB")
    lines.append(f"  Delta:             {result['mem_delta_mb']:+.1f} MB")
    lines.append("")
    lines.append("  --- Per-endpoint (top 5 slowest) ---")
    sorted_ep = sorted(result["per_endpoint"], key=lambda e: e["time_s"],
                       reverse=True)
    for ep in sorted_ep[:5]:
        lines.append(f"    {ep['method']:4} {ep['path']:20}  "
                     f"{ep['time_s']:.4f}s  reqs={ep['requests']}")

    if "multi_round" in result:
        mr = result["multi_round"]
        lines.append("")
        lines.append("  --- Multi-round stats ---")
        lines.append(f"  Rounds:            {mr['rounds']}")
        lines.append(f"  Wall time median:  {mr['wall_time_median_s']:.3f}s "
                     f"(stdev {mr['wall_time_stdev_s']:.3f})")
        lines.append(f"  Req/s median:      {mr['req_per_s_median']:.1f} "
                     f"(stdev {mr['req_per_s_stdev']:.1f})")

    lines.append("=" * 64)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="XSSentinel performance benchmark")
    parser.add_argument("--json", metavar="PATH",
                        help="Write JSON report to this file")
    parser.add_argument("--rounds", type=int, default=1,
                        help="Number of rounds (median is reported)")
    parser.add_argument("--max-payloads", type=int, default=14,
                        help="Payload budget per parameter")
    args = parser.parse_args()

    try:
        if args.rounds > 1:
            result = run_multi(rounds=args.rounds,
                               max_payloads=args.max_payloads)
        else:
            result = run_benchmark(max_payloads=args.max_payloads,
                                   label="single")
        print(format_report(result))

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"\n[+] JSON report written to {args.json}")
    finally:
        stop_server()


if __name__ == "__main__":
    main()
