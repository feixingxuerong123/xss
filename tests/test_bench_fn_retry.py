# -*- coding: utf-8 -*-
"""Phase 101: degraded-FN re-confirmation (retry with backoff).

Phase 97 retried an environment-shaped FN once, immediately.  On this
host a degradation window can outlast that single attempt (observed in
the p97 run: neg-rcdata-02 timed out twice and reproduced as TP in 13
requests standalone), so a run still reported FNs that are TPs when a
human re-runs them.  The retry now repeats up to FN_RETRY_MAX times
with FN_RETRY_WAIT seconds between attempts, and records EVERY attempt.

A FN that finishes normally (no error, normal request count) is never
retried -- real detection gaps must stay visible.
"""
import importlib.util
import json
import os
import sys
import types

import pytest

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _HERE)


def _load_runner(tmp_path, scripts):
    """Load run_benchmark_batched with a fake evaluate_case + 1 case."""
    out = str(tmp_path / "out.json")
    sys.argv = ["x", out, "1", "18999", "sync", "14", "12", "90"]
    spec = importlib.util.spec_from_file_location(
        "rbb_test", os.path.join(_HERE, "benchmark",
                                 "run_benchmark_batched.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.FN_RETRY_WAIT = 0.01              # keep the suite fast
    m.OUT = out
    m.load_cases = lambda: [{"id": "fake-01", "path": "/r/fake01",
                             "param": "q", "mode": "raw_element",
                             "ground_truth": "vulnerable",
                             "context": "html_element",
                             "difficulty": "easy"}]

    calls = {"n": 0, "timeouts": []}

    def _fake(base, c, timeout=0, max_payloads=0, max_transforms=0,
              engine="sync"):
        i = calls["n"]
        calls["n"] += 1
        calls["timeouts"].append(timeout)
        s = scripts[min(i, len(scripts) - 1)]
        return types.SimpleNamespace(
            case_id=c["id"], path=c["path"], param=c["param"],
            mode=c["mode"], ground_truth=c["ground_truth"],
            context=c["context"], difficulty=c["difficulty"],
            detected=bool(s["detected"]), verdict=s["verdict"],
            scan_time_s=s.get("scan_time_s", 1.0),
            findings_count=1 if s["detected"] else 0,
            requests=s.get("requests", 33), error=s.get("error", ""))

    m.evaluate_case = _fake
    return m, out, calls


_TIMEOUT_FN = {"verdict": "FN", "detected": False,
               "scan_time_s": 90.03, "requests": 0,
               "error": "timeout after 90s"}
_TP = {"verdict": "TP", "detected": True, "scan_time_s": 1.2, "requests": 33}
_CLEAN_FN = {"verdict": "FN", "detected": False, "scan_time_s": 5.0,
             "requests": 33, "error": ""}


def test_retry_recovers_on_second_attempt(tmp_path):
    m, out, calls = _load_runner(tmp_path, [_TIMEOUT_FN, _TP])
    m.main()
    rec = json.load(open(out, encoding="utf-8"))["cases"][0]
    assert rec["verdict"] == "TP", rec
    assert calls["n"] == 2
    assert len(rec["fn_retry"]["attempts"]) == 2
    # the FIRST (degraded) run is preserved for audit
    assert rec["fn_retry"]["attempts"][0]["error"] == "timeout after 90s"


def test_retry_exhausted_keeps_fn(tmp_path):
    m, out, calls = _load_runner(tmp_path, [_TIMEOUT_FN, _TIMEOUT_FN,
                                            _TIMEOUT_FN])
    m.main()
    rec = json.load(open(out, encoding="utf-8"))["cases"][0]
    assert rec["verdict"] == "FN", rec
    assert calls["n"] == m.FN_RETRY_MAX + 1, calls
    assert len(rec["fn_retry"]["attempts"]) == m.FN_RETRY_MAX + 1


def test_normal_finish_fn_is_never_retried(tmp_path):
    m, out, calls = _load_runner(tmp_path, [_CLEAN_FN])
    m.main()
    rec = json.load(open(out, encoding="utf-8"))["cases"][0]
    assert rec["verdict"] == "FN", rec
    assert calls["n"] == 1
    assert "fn_retry" not in rec, "a real code FN must stay untouched"


def test_retry_uses_a_wider_timeout(tmp_path):
    """The 'slow host' case (Phase 103): requests go out, the clock runs out.

    p101's neg-filter-06 timed out three times at 90s with requests=91
    and reproduced as TP in 0.83s standalone -- retrying it at the SAME
    ceiling just re-measures the slowness.  The retry must widen the
    timeout, and the record must say which ceiling each attempt used.
    """
    m, out, calls = _load_runner(tmp_path, [_TIMEOUT_FN, _TP])
    m.main()
    rec = json.load(open(out, encoding="utf-8"))["cases"][0]
    assert calls["timeouts"][0] == m.TIMEOUT
    assert calls["timeouts"][1] == int(m.TIMEOUT * m.FN_RETRY_TIMEOUT_SCALE), (
        f"retry reused the original ceiling {m.TIMEOUT}s -- a slow-host FN "
        f"can never be re-confirmed that way")
    attempts = rec["fn_retry"]["attempts"]
    assert attempts[1]["timeout"] == calls["timeouts"][1]


def test_meta_records_retry_policy(tmp_path):
    m, out, _ = _load_runner(tmp_path, [_TP])
    m.main()
    meta = json.load(open(out, encoding="utf-8"))["meta"]
    assert meta["fn_retry_on"] is True
    assert meta["fn_retry_max"] == m.FN_RETRY_MAX
    assert meta["fn_retry_wait"] == m.FN_RETRY_WAIT
    assert meta["fn_retry_timeout_scale"] == m.FN_RETRY_TIMEOUT_SCALE
