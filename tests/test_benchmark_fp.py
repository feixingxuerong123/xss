"""Regression tests: benchmark negative samples must NOT produce findings.

These tests ensure that future code changes don't reintroduce false positives
on the safe reflection patterns defined in benchmark/manifest.json.

Run: python -m pytest tests/test_benchmark_fp.py -v
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from benchmark.server import run_server, load_routes, BenchmarkHandler, DEFAULT_PORT

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MANIFEST_PATH = os.path.join(ROOT, "benchmark", "manifest.json")


def _load_negative_cases():
    """Load all ground_truth='safe' cases from the benchmark manifest."""
    with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    return [c for c in manifest["cases"] if c["ground_truth"] == "safe"]


_NEGATIVE_CASES = _load_negative_cases()


@pytest.fixture(scope="module")
def benchmark_server():
    """Start the benchmark server on a test port (module-scoped)."""
    # Phase 43: RUNTIME health gate — skip (not fail) when the loopback
    # has degraded mid-session.
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    from http.server import ThreadingHTTPServer
    port = 18877  # Use a non-standard port to avoid conflicts
    routes = load_routes()
    BenchmarkHandler.routes = routes
    # Threading, matching benchmark.server.run_server: this scanner holds a
    # requests.Session pool, and every connection it discards leaves the
    # handler blocked in readinto for `BenchmarkHandler.timeout` seconds on a
    # single-threaded server.  Measured as a ~15x slowdown of this file.
    server = ThreadingHTTPServer(("127.0.0.1", port), BenchmarkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Wait for readiness
    import http.client
    for _ in range(20):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                break
        except Exception:
            time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ---------------------------------------------------------------------------
# Parametrized regression tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case",
    _NEGATIVE_CASES,
    ids=[c["id"] for c in _NEGATIVE_CASES],
)
def test_no_false_positive(benchmark_server, case):
    """Scanner must NOT report any finding for a safe reflection case."""
    from xssentinel.core.scanner import Scanner
    from xssentinel.core.requester import Requester

    path = case["path"]
    param = case.get("param", "q")
    url = f"{benchmark_server}{path}?{param}=test"

    requester = Requester(timeout=10)
    # dom_engine="static": Playwright's sync API permanently marks the main
    # thread as having a running event loop (greenlet-based), which makes
    # every later asyncio.run() in the same pytest process raise
    # "cannot be called from a running event loop" -- that is what made the
    # async tests (test_p25 / test_scan_orchestration) fail full-suite runs
    # while passing individually.  These are reflection-FP regressions; the
    # static DOM engine is what they exercise.
    scanner = Scanner(
        requester=requester,
        max_payloads=8,
        max_transforms=4,
        dom_engine="static",
        verbose=False,
    )
    scanner.scan_target(url, method="GET", params={param: "test"},
                        data={}, oob_collect=False)
    scanner.dedup()

    # Filter out informational/low findings (CSP analysis, etc.)
    xss_findings = [
        f for f in scanner.findings
        if f.data.get("severity") in ("high", "medium", "critical")
        and not str(f.data.get("type", "")).startswith("csp_")
        and f.data.get("type") not in ("info",)
    ]

    assert len(xss_findings) == 0, (
        f"FALSE POSITIVE on {case['id']} ({case['mode']}): "
        f"expected 0 findings, got {len(xss_findings)}: "
        f"{[(f.data.get('type'), f.data.get('context'), str(f.data.get('payload',''))[:40]) for f in xss_findings]}"
    )


# ---------------------------------------------------------------------------
# Summary test (runs last, verifies overall FPR)
# ---------------------------------------------------------------------------

def test_overall_fpr_zero(benchmark_server):
    """Aggregate check: total FPR across all negative cases must be 0%."""
    from xssentinel.core.scanner import Scanner
    from xssentinel.core.requester import Requester

    fp_count = 0
    total = len(_NEGATIVE_CASES)

    for case in _NEGATIVE_CASES:
        path = case["path"]
        param = case.get("param", "q")
        url = f"{benchmark_server}{path}?{param}=test"

        requester = Requester(timeout=10)
        # dom_engine="static" -- see test_no_false_positive for the rationale
        # (Playwright sync API poisons the thread's event-loop state).
        scanner = Scanner(
            requester=requester,
            max_payloads=6,
            max_transforms=3,
            dom_engine="static",
            verbose=False,
        )
        scanner.scan_target(url, method="GET", params={param: "test"},
                            data={}, oob_collect=False)
        scanner.dedup()

        xss_findings = [
            f for f in scanner.findings
            if f.data.get("severity") in ("high", "medium", "critical")
            and not str(f.data.get("type", "")).startswith("csp_")
            and f.data.get("type") not in ("info",)
        ]
        if xss_findings:
            fp_count += 1

    fpr = fp_count / total if total > 0 else 0
    assert fpr == 0.0, (
        f"FPR regression: {fp_count}/{total} negative cases produced findings "
        f"(FPR={fpr:.2%}). Expected 0%."
    )
