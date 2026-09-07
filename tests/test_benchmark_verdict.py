"""Phase 69: benchmark verdict accounting.

A case the scanner cannot complete must NOT silently shrink the recall
denominator: a VULNERABLE case that errored out (timeout / killed loopback
connection) is a MISS (FN), while a SAFE case stays ERROR (a hung scan is
not evidence of a correct non-detection).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmark.runner as runner  # noqa: E402

VULN_CASE = {
    "id": "pos-x", "path": "/r/x", "param": "q", "mode": "raw_html",
    "ground_truth": "vulnerable", "context": "html_element",
    "difficulty": "easy",
}
SAFE_CASE = {
    "id": "neg-x", "path": "/r/s", "param": "q", "mode": "escaped",
    "ground_truth": "safe", "context": "html_element", "difficulty": "easy",
}


def _eval(case, monkeypatch, forced_error="timeout after 60s"):
    """Run evaluate_case with the subprocess layer forced to fail."""
    import subprocess as sp

    def boom(*a, **kw):
        raise sp.TimeoutExpired(cmd="x", timeout=60)

    monkeypatch.setattr(sp, "run", boom)
    return runner.evaluate_case("http://127.0.0.1:1", case, timeout=1,
                                max_payloads=2, max_transforms=1)


def test_vulnerable_case_that_errors_counts_as_fn(monkeypatch):
    r = _eval(VULN_CASE, monkeypatch)
    assert r.verdict == "FN", r.verdict
    assert r.error


def test_safe_case_that_errors_stays_error(monkeypatch):
    r = _eval(SAFE_CASE, monkeypatch)
    assert r.verdict == "ERROR", r.verdict


def test_detected_vulnerable_case_is_tp(monkeypatch):
    """Control: a completed scan with a finding is still TP (not FN)."""
    import json
    import subprocess as sp

    def ok(*a, **kw):
        out = kw["capture_output"]
        path = None
        for i, arg in enumerate(a[0]):
            if arg == "-o":
                path = a[0][i + 1]
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [
                    {"type": "reflected", "param": "q",
                     "url": "http://127.0.0.1:1/r/x?q=p",
                     "severity": "high"},
                ]}, fh)
        return sp.CompletedProcess(args=a[0], returncode=0, stdout="",
                                   stderr="")

    monkeypatch.setattr(sp, "run", ok)
    r = runner.evaluate_case("http://127.0.0.1:1", VULN_CASE, timeout=5,
                             max_payloads=2, max_transforms=1)
    assert r.verdict == "TP", (r.verdict, r.error)
