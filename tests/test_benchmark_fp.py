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


# ---------------------------------------------------------------------------
# The scorer itself: SKIP is a verdict, not a crash
# ---------------------------------------------------------------------------

class TestScoringHandlesSkipVerdict:
    """`--engine async` used to die on the first sync-only manifest case.

    `runner.evaluate_case` returns `verdict="SKIP"` for a case an engine does not
    implement (Phase 112: an engine is neither credited nor blamed for a vector it
    lacks).  Neither `_print_progress`'s icon table nor the by-context /
    by-difficulty buckets had a `skip` key, so the run raised
    `KeyError: 'SKIP'` / `KeyError: 'skip'` -- and a twelve-minute sweep produced
    no result file at all, which is why the async pipeline's accuracy has never
    been measured.  Six manifest cases declare `engines: ["sync"]`, so this was
    not a hypothetical path.
    """

    @staticmethod
    def _row(verdict, ground_truth, context="html_element", difficulty="easy"):
        from benchmark.runner import CaseResult
        return CaseResult(case_id="t-" + verdict, path="/r/x", param="q",
                          mode="raw_element", ground_truth=ground_truth,
                          context=context, difficulty=difficulty,
                          detected=verdict in ("TP", "FP"), verdict=verdict)

    def test_skip_row_survives_metrics_and_progress(self, capsys):
        from benchmark.runner import _compute_metrics, _print_progress
        # every context stated explicitly: `_row` has a default, and a test that
        # counts rows per context must not depend on remembering it
        rows = [self._row("SKIP", "safe", context="html_element"),
                self._row("TP", "vulnerable", context="html_element"),
                self._row("TN", "safe", context="url_href"),
                self._row("ERROR", "safe", context="url_href",
                          difficulty="hard"),
                self._row("FN", "vulnerable", context="event_handler")]
        m = _compute_metrics(rows, 12.0)
        assert m.by_context["html_element"]["skip"] == 1
        assert m.by_context["html_element"]["total"] == 2
        assert m.by_context["url_href"]["total"] == 2, "ERROR needs a bucket too"
        for i, r in enumerate(rows, 1):
            _print_progress(i, len(rows), r)          # must not raise
        out = capsys.readouterr().out
        assert "[-]" in out, "a skipped case has no progress marker"

    def test_rates_ignore_skipped_but_the_count_stays_visible(self):
        """recall/precision are computed over what RAN; the artifact has to say
        how much did not run, or 192 manifest cases and 185 scored ones look
        identical."""
        from benchmark.runner import _compute_metrics
        rows = [self._row("TP", "vulnerable")] + \
               [self._row("SKIP", "vulnerable", context=f"c{i}")
                for i in range(5)]
        m = _compute_metrics(rows, 1.0)
        assert m.recall == 1.0 and m.fn == 0
        assert sum(s["skip"] for s in m.by_context.values()) == 5
        assert sum(s["total"] for s in m.by_context.values()) == 6


# ---------------------------------------------------------------------------
# The retry policy itself: an unfinished scan is re-measured in BOTH classes
# ---------------------------------------------------------------------------

class TestErroredCasesGetRetriedInBothClasses:
    """A scan the harness could not finish is retried whether ground truth says
    "vulnerable" or "safe".

    The Phase 69 retry loop was conditioned on ``verdict == "FN"``, so only
    errored *vulnerable* cases were re-run.  A 90 s timeout on a safe case --
    ``neg-graphql-01`` in the 192-case run -- was accepted on the first attempt
    and then dropped out of the denominator, so one flaky loopback read as "1
    fewer case measured" instead of "1 case worth trying again" (it scanned
    clean in 9.2 s when re-run on its own).

    The counterpart assertions below are the point of the class: exhausting the
    budget must leave the honest verdict in place.  Re-trying is not a licence
    to call a scan that never finished a correct non-detection.
    """

    @staticmethod
    def _row(verdict, ground_truth, error=""):
        from benchmark.runner import CaseResult
        return CaseResult(case_id="neg-retry-01", path="/s/x", param="q",
                          mode="raw_element", ground_truth=ground_truth,
                          context="html_element", difficulty="easy",
                          detected=verdict in ("TP", "FP"), verdict=verdict,
                          error=error)

    @staticmethod
    def _script(monkeypatch, rows):
        """Hand back `rows` in order (repeating the last one) and record calls."""
        import benchmark.runner as runner
        calls = []

        def fake(base_url, case, timeout, max_payloads, max_transforms,
                 engine="sync"):
            calls.append({"case": case["id"], "engine": engine,
                          "timeout": timeout})
            return rows[min(len(calls) - 1, len(rows) - 1)]

        monkeypatch.setattr(runner, "evaluate_case", fake)
        return calls

    def test_errored_safe_case_is_measured_again(self, monkeypatch):
        import benchmark.runner as runner
        calls = self._script(monkeypatch, [
            self._row("ERROR", "safe", error="timeout after 90s"),
            self._row("TN", "safe"),
        ])
        r = runner._evaluate_with_retries("http://127.0.0.1:9",
                                          {"id": "neg-graphql-01"},
                                          90, 14, 12, "sync")
        assert len(calls) == 2, "an errored safe case used to stop at one try"
        assert r.verdict == "TN" and not r.error
        assert r.retries == 1, "the row must say this answer arrived on try two"

    def test_errored_vulnerable_case_still_retried_on_named_engine(
            self, monkeypatch):
        """Phase 69 behaviour preserved, and the retry stays on the engine it
        was asked for -- a retry that silently fell back to `sync` would be
        measuring a different engine than the one being scored."""
        import benchmark.runner as runner
        calls = self._script(monkeypatch, [
            self._row("FN", "vulnerable", error="scanner killed"),
            self._row("TP", "vulnerable"),
        ])
        r = runner._evaluate_with_retries("http://127.0.0.1:9",
                                          {"id": "pos-x-01"},
                                          45, 14, 12, "async")
        assert len(calls) == 2
        assert {c["engine"] for c in calls} == {"async"}
        assert {c["timeout"] for c in calls} == {45}
        assert r.verdict == "TP"

    def test_answered_case_is_not_wasted_on_a_retry(self, monkeypatch):
        import benchmark.runner as runner
        calls = self._script(monkeypatch, [self._row("FP", "safe")])
        r = runner._evaluate_with_retries("http://127.0.0.1:9",
                                          {"id": "neg-y-01"},
                                          90, 14, 12, "sync")
        assert len(calls) == 1, "a completed scan must not be re-run"
        assert r.retries == 0
        assert r.verdict == "FP", "a retry loop must not soften a false positive"

    def test_exhausted_budget_leaves_safe_case_error_not_tn(self, monkeypatch):
        import benchmark.runner as runner
        calls = self._script(monkeypatch, [
            self._row("ERROR", "safe", error="timeout after 90s")])
        r = runner._evaluate_with_retries("http://127.0.0.1:9",
                                          {"id": "neg-z-01"},
                                          90, 14, 12, "sync")
        assert len(calls) == 1 + runner._ERROR_RETRIES
        assert r.retries == runner._ERROR_RETRIES
        assert r.verdict == "ERROR"
        assert r.error == "timeout after 90s"

    def test_exhausted_budget_leaves_vulnerable_case_fn(self, monkeypatch):
        """A vulnerability never evaluated is still a miss, not a free pass --
        the asymmetry against the safe case above is deliberate and is the
        reason `ERROR` had to stay visible in the aggregate."""
        import benchmark.runner as runner
        self._script(monkeypatch, [
            self._row("FN", "vulnerable", error="timeout after 90s")])
        r = runner._evaluate_with_retries("http://127.0.0.1:9",
                                          {"id": "pos-w-01"},
                                          90, 14, 12, "sync")
        assert r.verdict == "FN"

